// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Lazy Zero-Bloat Adreno GPU Stack (`msm_kgsl`) & External App/DOOM Launcher
//! for `Pulih` Recovery (`SPEC-0051` + GPU/DOOM Extension).
//!
//! Architecture:
//! - **0 bytes added to `recovery.img`**, **0 KB RAM & 0 ms boot delay while OFF**.
//! - Lazily mounts the active slot's read-only `vendor_dlkm` (`/mnt/vdlkm_ro`) and
//!   `vendor` (`/mnt/vendor_ro`) via `dm-linear` (`pasang_core::lp`) or existing mounts,
//!   exposes Adreno GMU/SQE firmware, and loads `governor_msm_adreno_tz.ko` + `msm_kgsl.ko`.
//! - Exposes `/dev/kgsl-3d0`, `/dev/dri/card0`, `/dev/dri/renderD128`, live GPU
//!   clock/temp/load telemetry, and full Adreno EGL/GLES/Vulkan `LD_LIBRARY_PATH`
//!   environment ready to run native ARM64 ports (e.g. DOOM / SDL2 / Vulkan / WPE)!
//! - Enforces anti-brick safety: refuses active-slot writes while ro vendor is mounted
//!   and provides clean `disable()` teardown (`rmmod` + `umount`).

use crate::super_mount::{
    expose_firmware_by_prefix, load_module_with_deps, mount_super_ro, remove_dm_device,
};
use std::fs;
use std::path::Path;
use std::process::Command;

/// Kernel modules loaded lazily in strict dependency order from `/vendor_dlkm/lib/modules/`.
pub const KGSL_MODULE_ORDER: &[&str] = &[
    "gpucc-tuna.ko",
    "governor_msm_adreno_tz.ko",
    "governor_gpubw_mon.ko",
    "msm_kgsl.ko",
];

pub const VDLKM_RO_MOUNT: &str = "/vendor_dlkm";
pub const VENDOR_RO_MOUNT: &str = "/mnt/vendor_ro";
pub const KGSL_DEV: &str = "/dev/kgsl-3d0";
pub const KGSL_SYSFS: &str = "/sys/class/kgsl/kgsl-3d0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GpuDriverState {
    Off,
    Active,
}

/// Live Adreno GPU telemetry read from `/sys/class/kgsl/kgsl-3d0/`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GpuTelemetry {
    pub kgsl_present: bool,
    pub dri_render_present: bool,
    pub model: String,
    pub cur_mhz: u64,
    pub min_mhz: u64,
    pub max_mhz: u64,
    pub temp_tenths_c: i32,
    pub gpu_busy_pct: u32,
    pub governor: String,
    pub available_mhz: Vec<u64>,
}

impl GpuTelemetry {
    pub fn probe(sysfs_kgsl: &Path, dev_kgsl: &Path, dev_render: &Path) -> Self {
        let kgsl_present = dev_kgsl.exists() || sysfs_kgsl.is_dir();
        let dri_render_present = dev_render.exists();
        if !sysfs_kgsl.is_dir() {
            return Self {
                kgsl_present,
                dri_render_present,
                model: if dri_render_present {
                    "DRM/KMS (kgsl OFF - tap Enable GPU)".into()
                } else {
                    "Unavailable".into()
                },
                ..Default::default()
            };
        }

        let read_s = |rel: &str| {
            fs::read_to_string(sysfs_kgsl.join(rel))
                .unwrap_or_default()
                .trim()
                .to_string()
        };
        let read_u64 = |rel: &str| read_s(rel).parse::<u64>().unwrap_or(0);

        let model = {
            let m = read_s("gpu_model");
            if m.is_empty() { "Adreno (kgsl-3d0)".into() } else { m }
        };
        let cur_hz = read_u64("devfreq/cur_freq");
        let min_hz = read_u64("devfreq/min_freq");
        let max_hz = read_u64("devfreq/max_freq");
        let temp_raw = read_s("temp").parse::<i32>().unwrap_or(0);
        // Some kernels expose millidegrees C (e.g. 38500), others tenths C (385).
        let temp_tenths_c = if temp_raw > 1000 { temp_raw / 100 } else { temp_raw };
        let gpu_busy_pct = read_s("gpu_busy_percentage")
            .trim_end_matches('%')
            .trim()
            .parse::<u32>()
            .unwrap_or(0);
        let governor = read_s("devfreq/governor");
        let mut available_mhz: Vec<u64> = read_s("devfreq/available_frequencies")
            .split_whitespace()
            .filter_map(|t| t.parse::<u64>().ok())
            .map(|hz| hz / 1_000_000)
            .collect();
        available_mhz.sort_unstable();
        available_mhz.dedup();

        Self {
            kgsl_present,
            dri_render_present,
            model,
            cur_mhz: cur_hz / 1_000_000,
            min_mhz: min_hz / 1_000_000,
            max_mhz: max_hz / 1_000_000,
            temp_tenths_c,
            gpu_busy_pct,
            governor,
            available_mhz,
        }
    }

    pub fn read_live() -> Self {
        Self::probe(
            Path::new(KGSL_SYSFS),
            Path::new(KGSL_DEV),
            Path::new("/dev/dri/renderD128"),
        )
    }
}

/// Manages lazy zero-bloat Adreno GPU lifecycle in Pulih Recovery.
#[derive(Clone, Debug)]
pub struct GpuManager {
    pub state: GpuDriverState,
    pub ro_vendor_mounted: bool,
    pub ro_vdlkm_mounted: bool,
    pub active_slot_suffix: String,
}

impl Default for GpuManager {
    fn default() -> Self {
        let already_up = Path::new(KGSL_DEV).exists() || Path::new(KGSL_SYSFS).is_dir();
        Self {
            state: if already_up {
                GpuDriverState::Active
            } else {
                GpuDriverState::Off
            },
            ro_vendor_mounted: false,
            ro_vdlkm_mounted: false,
            active_slot_suffix: "_a".into(),
        }
    }
}

impl GpuManager {
    /// Environment variables passed to GPU-accelerated recovery apps / DOOM ports
    /// so EGL, GLESv2/v3, Vulkan (`vulkan.adreno.so`), and DRM work with zero ramdisk bloat!
    pub fn app_launch_env(&self, width: u32, height: u32, refresh_hz: u32) -> Vec<(String, String)> {
        vec![
            (
                "LD_LIBRARY_PATH".into(),
                format!(
                    "{v}/lib64:{v}/lib64/egl:{v}/lib64/hw:/vendor/lib64:/system/lib64",
                    v = VENDOR_RO_MOUNT
                ),
            ),
            ("PULIH_GPU_KGSL".into(), KGSL_DEV.into()),
            ("PULIH_DRM_CARD".into(), "/dev/dri/card0".into()),
            ("PULIH_DRM_RENDER".into(), "/dev/dri/renderD128".into()),
            ("PULIH_FB_WIDTH".into(), width.to_string()),
            ("PULIH_FB_HEIGHT".into(), height.to_string()),
            ("PULIH_FB_HZ".into(), refresh_hz.to_string()),
            ("SDL_VIDEODRIVER".into(), "kmsdrm".into()),
            ("SDL_AUDIODRIVER".into(), "dummy".into()),
        ]
    }

    /// Enable Adreno GPU (`msm_kgsl.ko`) from active slot's read-only `vendor_dlkm` & `vendor`
    /// (auto-mapped from `super` via `dm-linear` if not yet mapped!).
    pub fn enable_lazy(&mut self) -> Result<GpuTelemetry, String> {
        if Path::new(KGSL_DEV).exists() && Path::new(KGSL_SYSFS).is_dir() {
            self.state = GpuDriverState::Active;
            return Ok(GpuTelemetry::read_live());
        }

        let suf = self.active_slot_suffix.as_str();

        // 1. Auto-map & mount active vendor_dlkm (at /vendor_dlkm) and vendor (at /mnt/vendor_ro) RO
        if !Path::new("/vendor_dlkm/lib/modules/msm_kgsl.ko").exists() {
            match mount_super_ro("vendor_dlkm", suf, VDLKM_RO_MOUNT) {
                Ok(fresh) => {
                    if fresh {
                        self.ro_vdlkm_mounted = true;
                    }
                }
                Err(e) => {
                    return Err(format!("vendor_dlkm RO mount failed: {e}"));
                }
            }
        }
        if let Ok(fresh) = mount_super_ro("vendor", suf, VENDOR_RO_MOUNT) {
            if fresh {
                self.ro_vendor_mounted = true;
            }
        }
        // Expose Adreno GMU / SQE / AQE / ZAP firmware into /lib/firmware BEFORE insmod!
        let _ = expose_firmware_by_prefix(
            &Path::new(VENDOR_RO_MOUNT).join("firmware"),
            &["gen7", "gen8", "a7", "a8", "gmu", "sqe", "aqe", "zap", "adreno"],
        );

        // 2. Load Adreno governor + kgsl kernel modules with full modules.dep resolution
        let mod_dirs: &[&Path] = &[
            Path::new("/vendor_dlkm/lib/modules"),
            Path::new("/mnt/vdlkm_ro/lib/modules"),
            Path::new("/lib/modules"),
        ];
        for ko in KGSL_MODULE_ORDER {
            let res = load_module_with_deps(ko, mod_dirs);
            if *ko == "msm_kgsl.ko" {
                res?;
            }
        }

        // Wait briefly for ueventd/sysfs to create /dev/kgsl-3d0 & /sys/class/kgsl/kgsl-3d0
        for _ in 0..10 {
            if Path::new(KGSL_DEV).exists() && Path::new(KGSL_SYSFS).is_dir() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(30));
        }

        self.state = GpuDriverState::Active;
        Ok(GpuTelemetry::read_live())
    }

    /// Cleanly unload `msm_kgsl.ko` and unmount read-only `vendor_dlkm`/`vendor`
    /// before any active-slot OTA flash (anti-brick safety invariant!).
    pub fn disable_safe(&mut self) {
        let _ = Command::new("/system/bin/rmmod").arg("msm_kgsl").status();
        let _ = Command::new("/system/bin/rmmod")
            .arg("governor_gpubw_mon")
            .status();
        let _ = Command::new("/system/bin/rmmod")
            .arg("governor_msm_adreno_tz")
            .status();
        let suf = self.active_slot_suffix.clone();
        if self.ro_vdlkm_mounted {
            let _ = Command::new("/system/bin/umount").arg(VDLKM_RO_MOUNT).status();
            remove_dm_device(&format!("vendor_dlkm{suf}"));
            self.ro_vdlkm_mounted = false;
        }
        if self.ro_vendor_mounted {
            let _ = Command::new("/system/bin/umount").arg(VENDOR_RO_MOUNT).status();
            remove_dm_device(&format!("vendor{suf}"));
            self.ro_vendor_mounted = false;
        }
        self.state = GpuDriverState::Off;
    }

    /// Returns `true` if read-only vendor mounts are active (used by anti-brick slot guard).
    pub fn holds_active_slot_ro_mounts(&self) -> bool {
        self.ro_vendor_mounted || self.ro_vdlkm_mounted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probes_mock_adreno_kgsl_telemetry_and_doom_launch_env() {
        let tmp = std::env::temp_dir().join(format!("pulih_gpu_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        let kgsl = tmp.join("kgsl-3d0");
        fs::create_dir_all(kgsl.join("devfreq")).unwrap();
        fs::write(kgsl.join("gpu_model"), "Adreno825\n").unwrap();
        fs::write(kgsl.join("temp"), "39200\n").unwrap();
        fs::write(kgsl.join("gpu_busy_percentage"), " 12 %\n").unwrap();
        fs::write(kgsl.join("devfreq/cur_freq"), "515000000\n").unwrap();
        fs::write(kgsl.join("devfreq/min_freq"), "150000000\n").unwrap();
        fs::write(kgsl.join("devfreq/max_freq"), "1162000000\n").unwrap();
        fs::write(kgsl.join("devfreq/governor"), "msm-adreno-tz\n").unwrap();
        fs::write(
            kgsl.join("devfreq/available_frequencies"),
            "1162000000 763000000 515000000 300000000 150000000\n",
        )
        .unwrap();

        let t = GpuTelemetry::probe(&kgsl, Path::new("/nonexistent"), Path::new("/nonexistent"));
        assert!(t.kgsl_present);
        assert_eq!(t.model, "Adreno825");
        assert_eq!(t.cur_mhz, 515);
        assert_eq!(t.min_mhz, 150);
        assert_eq!(t.max_mhz, 1162);
        assert_eq!(t.temp_tenths_c, 392);
        assert_eq!(t.gpu_busy_pct, 12);
        assert_eq!(t.available_mhz, vec![150, 300, 515, 763, 1162]);

        let mgr = GpuManager::default();
        let env = mgr.app_launch_env(1280, 2772, 120);
        assert!(env.iter().any(|(k, v)| k == "SDL_VIDEODRIVER" && v == "kmsdrm"));
        assert!(env.iter().any(|(k, v)| k == "LD_LIBRARY_PATH" && v.contains("/mnt/vendor_ro/lib64/egl")));
        assert!(env.iter().any(|(k, v)| k == "PULIH_DRM_CARD" && v == "/dev/dri/card0"));

        let _ = fs::remove_dir_all(&tmp);
    }
}
