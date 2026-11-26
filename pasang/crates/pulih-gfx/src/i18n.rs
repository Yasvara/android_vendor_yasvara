// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Static bilingual (`en_US` + `id_ID`) string table for `Pulih` Recovery.
//! Zero runtime heap allocation, zero emojis.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Locale {
    EnUs = 0,
    IdId = 1,
}

impl Locale {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Locale::IdId,
            _ => Locale::EnUs,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StrKey {
    AppName,
    TabHome,
    TabFiles,
    TabPartitions,
    TabTools,
    InstallFlash,
    FileManager,
    PartitionsMount,
    RootModules,
    Backup,
    Wipe,
    SwitchSlot,
    Reboot,
    RebootSystem,
    RebootBootloader,
    RebootFastbootd,
    PowerOff,
    AdbRootOn,
    WifiOff,
    WifiOn,
    OtgReady,
    SwipeToConfirm,
    Confirmed,
    BootloopDetected,
    SuperFree,
    SlotA,
    SlotB,
    JelajahBrowser,
    LanWebDrop,
    Terminal,
    DevicePassport,
    Settings,
    SafeModeDisableAll,
    OledBlack,
    Language,
    Cancel,
}

pub fn t(locale: Locale, key: StrKey) -> &'static str {
    use Locale::*;
    use StrKey::*;
    match (locale, key) {
        (_, AppName) => "Pulih",
        (EnUs, TabHome) => "Home",
        (IdId, TabHome) => "Beranda",
        (EnUs, TabFiles) => "Files",
        (IdId, TabFiles) => "Berkas",
        (EnUs, TabPartitions) => "Parts",
        (IdId, TabPartitions) => "Partisi",
        (EnUs, TabTools) => "Tools",
        (IdId, TabTools) => "Alat",
        (EnUs, InstallFlash) => "Install & Flash",
        (IdId, InstallFlash) => "Pasang & Flash",
        (EnUs, FileManager) => "File Manager",
        (IdId, FileManager) => "Manajer Berkas",
        (EnUs, PartitionsMount) => "Partitions & Mount",
        (IdId, PartitionsMount) => "Partisi & Mount",
        (EnUs, RootModules) => "Root Modules",
        (IdId, RootModules) => "Modul Root",
        (EnUs, Backup) => "Backup",
        (IdId, Backup) => "Cadangkan",
        (EnUs, Wipe) => "Wipe",
        (IdId, Wipe) => "Hapus",
        (EnUs, SwitchSlot) => "Switch Slot",
        (IdId, SwitchSlot) => "Ganti Slot",
        (EnUs, Reboot) => "Reboot",
        (IdId, Reboot) => "Mulai Ulang",
        (EnUs, RebootSystem) => "Reboot System",
        (IdId, RebootSystem) => "Masuk Sistem",
        (EnUs, RebootBootloader) => "Bootloader",
        (IdId, RebootBootloader) => "Bootloader",
        (EnUs, RebootFastbootd) => "Fastbootd",
        (IdId, RebootFastbootd) => "Fastbootd",
        (EnUs, PowerOff) => "Power Off",
        (IdId, PowerOff) => "Matikan",
        (EnUs, AdbRootOn) => "ADB ROOT",
        (IdId, AdbRootOn) => "ADB ROOT",
        (EnUs, WifiOff) => "Wi-Fi Off",
        (IdId, WifiOff) => "Wi-Fi Mati",
        (EnUs, WifiOn) => "Wi-Fi 7",
        (IdId, WifiOn) => "Wi-Fi 7",
        (EnUs, OtgReady) => "OTG",
        (IdId, OtgReady) => "OTG",
        (EnUs, SwipeToConfirm) => "Swipe right to confirm",
        (IdId, SwipeToConfirm) => "Geser kanan untuk konfirmasi",
        (EnUs, Confirmed) => "Confirmed",
        (IdId, Confirmed) => "Dikonfirmasi",
        (EnUs, BootloopDetected) => "Bootloop Detected - Recovery Actions Ready",
        (IdId, BootloopDetected) => "Bootloop Terdeteksi - Aksi Pemulihan Siap",
        (EnUs, SuperFree) => "super free",
        (IdId, SuperFree) => "ruang super",
        (_, SlotA) => "Slot A",
        (_, SlotB) => "Slot B",
        (EnUs, JelajahBrowser) => "Jelajah Browser",
        (IdId, JelajahBrowser) => "Peramban Jelajah",
        (EnUs, LanWebDrop) => "Wi-Fi LAN Web-Drop",
        (IdId, LanWebDrop) => "Web-Drop Wi-Fi LAN",
        (_, Terminal) => "Terminal",
        (EnUs, DevicePassport) => "Device Passport",
        (IdId, DevicePassport) => "Paspor Perangkat",
        (EnUs, Settings) => "Settings",
        (IdId, Settings) => "Setelan",
        (EnUs, SafeModeDisableAll) => "Disable All Modules (Safe Mode)",
        (IdId, SafeModeDisableAll) => "Matikan Semua Modul (Mode Aman)",
        (EnUs, OledBlack) => "OLED True Black",
        (IdId, OledBlack) => "Hitam Pekat OLED",
        (EnUs, Language) => "Language",
        (IdId, Language) => "Bahasa",
        (EnUs, Cancel) => "Cancel",
        (IdId, Cancel) => "Batal",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bilingual_strings_non_empty_and_no_emojis() {
        let keys = [
            StrKey::AppName,
            StrKey::TabHome,
            StrKey::TabFiles,
            StrKey::TabPartitions,
            StrKey::TabTools,
            StrKey::InstallFlash,
            StrKey::SwipeToConfirm,
            StrKey::BootloopDetected,
        ];
        for k in keys {
            for loc in [Locale::EnUs, Locale::IdId] {
                let s = t(loc, k);
                assert!(!s.is_empty());
                assert!(s.chars().all(|c| (c as u32) < 0x1F000), "emoji found in {s}");
            }
        }
    }
}
