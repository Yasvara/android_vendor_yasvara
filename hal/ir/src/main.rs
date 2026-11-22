//
// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0
//

//! Lazy Rust ConsumerIR AIDL HAL (`android.hardware.ir.IConsumerIr/default`).
//!
//! Starts on demand via `servicemanager` + `oneshot`/`disabled` init service and exits to 0 KB
//! RAM as soon as `ConsumerIrService` releases its idle Binder reference.

use std::ffi::CString;
use std::io;

use android_hardware_ir::aidl::android::hardware::ir::{
    ConsumerIrFreqRange::ConsumerIrFreqRange,
    IConsumerIr::{BnConsumerIr, IConsumerIr},
};
use binder::{register_lazy_service, BinderFeatures, ExceptionCode, Interface, ProcessState, Status};
use log::{error, info, LevelFilter};
use rustutils::android::system_properties;

const SERVICE_NAME: &str = "android.hardware.ir.IConsumerIr/default";
const IR_DEVICE_PATH: &str = "/dev/lirc0";
const PROP_CARRIER_FREQS: &str = "ro.vendor.ir.carrier_freqs";

/// `_IOW('i', 0x13, __u32)` from `<linux/lirc.h>`.
const LIRC_SET_SEND_CARRIER: libc::c_int = 0x4004_6913u32 as libc::c_int;

struct ConsumerIr {
    ranges: Vec<ConsumerIrFreqRange>,
}

impl ConsumerIr {
    fn new() -> Self {
        let mut ranges = Vec::new();
        if let Ok(Some(raw)) = system_properties::read(PROP_CARRIER_FREQS) {
            let nums: Vec<i32> = raw
                .split(',')
                .filter_map(|tok| tok.trim().parse::<i32>().ok())
                .collect();
            for pair in nums.chunks_exact(2) {
                if pair[0] > 0 && pair[1] >= pair[0] {
                    ranges.push(ConsumerIrFreqRange { minHz: pair[0], maxHz: pair[1] });
                }
            }
        }
        if ranges.is_empty() {
            ranges.push(ConsumerIrFreqRange { minHz: 30_000, maxHz: 60_000 });
        }
        Self { ranges }
    }

    fn is_in_range(&self, freq_hz: i32) -> bool {
        self.ranges.iter().any(|r| freq_hz >= r.minHz && freq_hz <= r.maxHz)
    }
}

impl Interface for ConsumerIr {}

impl IConsumerIr for ConsumerIr {
    fn getCarrierFreqs(&self) -> binder::Result<Vec<ConsumerIrFreqRange>> {
        Ok(self
            .ranges
            .iter()
            .map(|r| ConsumerIrFreqRange { minHz: r.minHz, maxHz: r.maxHz })
            .collect())
    }

    fn transmit(&self, carrier_freq_hz: i32, pattern: &[i32]) -> binder::Result<()> {
        if pattern.is_empty() {
            return Ok(());
        }
        if !self.is_in_range(carrier_freq_hz) {
            error!("Unsupported IR carrier frequency: {carrier_freq_hz}");
            return Err(Status::new_exception_str(
                ExceptionCode::UNSUPPORTED_OPERATION,
                Some("Unsupported carrier frequency"),
            ));
        }

        let dev_path = CString::new(IR_DEVICE_PATH).expect("static path has no NUL");
        // SAFETY: `dev_path` is a valid NUL-terminated C string.
        let fd = unsafe { libc::open(dev_path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
        if fd < 0 {
            let err = io::Error::last_os_error();
            error!("Failed to open {IR_DEVICE_PATH}: {err}");
            return Err(Status::new_exception_str(
                ExceptionCode::ILLEGAL_STATE,
                Some("Failed to open IR device"),
            ));
        }

        // Kernel expects an odd number of alternating on/off periods (ending on a pulse).
        let entries = if pattern.len() % 2 == 0 { pattern.len() - 1 } else { pattern.len() };
        let carrier_u32 = carrier_freq_hz as u32;

        // SAFETY: `fd` is a valid open descriptor on `/dev/lirc0`; `&carrier_u32` is a valid
        // pointer to `__u32` as required by `LIRC_SET_SEND_CARRIER`.
        let ioctl_rc = unsafe { libc::ioctl(fd, LIRC_SET_SEND_CARRIER, &carrier_u32) };
        if ioctl_rc < 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            error!("LIRC_SET_SEND_CARRIER({carrier_freq_hz}) failed: {err}");
            return Err(Status::new_exception_str(
                ExceptionCode::UNSUPPORTED_OPERATION,
                Some("Failed to set carrier frequency"),
            ));
        }

        let byte_len = entries * std::mem::size_of::<i32>();
        // SAFETY: `pattern` has at least `entries` initialized `i32` values (`entries <= pattern.len()`).
        let write_rc = unsafe {
            libc::write(fd, pattern.as_ptr().cast::<libc::c_void>(), byte_len)
        };
        let write_err = if write_rc < 0 { Some(io::Error::last_os_error()) } else { None };
        // SAFETY: `fd` is open and owned by this function.
        unsafe { libc::close(fd) };

        if let Some(err) = write_err {
            error!("Failed to write IR pattern ({entries} entries): {err}");
            return Err(Status::new_exception_str(
                ExceptionCode::ILLEGAL_STATE,
                Some("Failed to transmit IR pattern"),
            ));
        }

        Ok(())
    }
}

fn main() {
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("YasvaraIR")
            .with_max_level(LevelFilter::Info)
            .with_log_buffer(android_logger::LogId::System),
    );

    ProcessState::start_thread_pool();
    let service = BnConsumerIr::new_binder(ConsumerIr::new(), BinderFeatures::default());
    if let Err(e) = register_lazy_service(SERVICE_NAME, service.as_binder()) {
        error!("Failed to register lazy service {SERVICE_NAME}: {e:?}");
        std::process::exit(1);
    }
    info!("Registered lazy {SERVICE_NAME}");
    ProcessState::join_thread_pool();
}
