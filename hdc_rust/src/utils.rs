/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//! utils
#![allow(missing_docs)]

use crate::config::SHELL_PROG;

use std::io::{self, Error, ErrorKind};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use ylong_runtime::io::AsyncWriteExt;

pub fn get_pseudo_random_u32() -> u32 {
    (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        & 0xffffffff) as u32
}

pub fn get_current_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

pub async fn print_msg(buf: Vec<u8>) -> io::Result<()> {
    let mut stdout = ylong_runtime::io::stdout();
    let _ = stdout.write(&buf).await;
    let _ = stdout.flush().await;
    Ok(())
}

pub fn execute_cmd(cmd: String) -> Vec<u8> {
    let arg_sign = if cfg!(target_os = "windows") {
        "/c"
    } else {
        "-c"
    };
    let result = Command::new(SHELL_PROG).args([arg_sign, &cmd]).output();

    match result {
        Ok(output) => [output.stdout, output.stderr].concat(),
        Err(e) => e.to_string().into_bytes(),
    }
}

pub fn error_other(msg: String) -> Error {
    Error::new(ErrorKind::Other, msg)
}

pub mod hdc_log {
    pub use hilog_rust::{hilog, HiLogLabel, LogType};
    pub use std::ffi::{c_char, CString};

    pub const LOG_LABEL: HiLogLabel = HiLogLabel {
        log_type: LogType::LogCore,
        domain: 0xD002D13,
        tag: "HDC_LOG",
    };

    #[macro_export]
    macro_rules! trace {
        ($($arg:tt)+) => {
            if(cfg!(feature = "daemon")) {
                let head = format!("{}:{}", file!().split('/').last().unwrap(), line!());
                hilog_rust::info!(LOG_LABEL, "{} {}", @public(head), @public(format!($($arg)+)));
            }
            log::trace!($($arg)+);
        };
    }

    #[macro_export]
    macro_rules! debug {
        ($($arg:tt)+) => {
            if(cfg!(feature = "daemon")) {
                let head = format!("{}:{}", file!().split('/').last().unwrap(), line!());
                hilog_rust::info!(LOG_LABEL, "{} {}", @public(head), @public(format!($($arg)+)));
            }
            log::debug!($($arg)+);
        };
    }

    #[macro_export]
    macro_rules! info {
        ($($arg:tt)+) => {
            if(cfg!(feature = "daemon")) {
                let head = format!("{}:{}", file!().split('/').last().unwrap(), line!());
                hilog_rust::info!(LOG_LABEL, "{} {}", @public(head), @public(format!($($arg)+)));
            }
            log::info!($($arg)+);
        };
    }

    #[macro_export]
    macro_rules! warn {
        ($($arg:tt)+) => {
            if (cfg!(feature = "daemon")) {
                let head = format!("{}:{}", file!().split('/').last().unwrap(), line!());
                hilog_rust::warn!(LOG_LABEL, "{} {}", @public(head), @public(format!($($arg)+)));
            }
            log::warn!($($arg)+);
        };
    }

    #[macro_export]
    macro_rules! error {
        ($($arg:tt)+) => {
            if (cfg!(feature = "daemon")) {
                let head = format!("{}:{}", file!().split('/').last().unwrap(), line!());
                hilog_rust::error!(LOG_LABEL, "{} {}", @public(head), @public(format!($($arg)+)));
            }
            log::error!($($arg)+);
        };
    }

    #[macro_export]
    macro_rules! fatal {
        ($($arg:tt)+) => {
            if(cfg!(feature = "daemon")) {
                let head = format!("{}:{}", file!().split('/').last().unwrap(), line!());
                hilog_rust::fatal!(LOG_LABEL, "{} {}", @public(head), @public(format!($($arg)+)));
            }
            log::fatal!($($arg)+);
        };
    }

    // pub use crate::{trace, debug, info, warn, error, fatal};
}