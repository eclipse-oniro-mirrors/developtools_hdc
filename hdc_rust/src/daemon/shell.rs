/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
//! shell
#![allow(missing_docs)]

use crate::utils::hdc_log::*;
use hdc::config::TaskMessage;
use hdc::config::{HdcCommand, SHELL_PROG, SHELL_TEMP};
use hdc::transfer;

use std::collections::HashMap;
use std::io::{self};
use std::sync::{Arc, Mutex};

use ylong_runtime::sync::mpsc;
use ylong_runtime::process::pty_process::{Pty, PtyCommand};
use ylong_runtime::io::AsyncReadExt;
use ylong_runtime::io::AsyncWriteExt;
use ylong_runtime::process::Child as ylongChild;

nix::ioctl_write_ptr_bad!(set_term_size, libc::TIOCSWINSZ, nix::pty::Winsize);

nix::ioctl_write_ptr_bad!(set_controlling_terminal, libc::TIOCSCTTY, libc::c_int);

pub struct PtyTask {
    pub handle: ylong_runtime::task::JoinHandle<()>,
    pub tx: mpsc::BoundedSender<Vec<u8>>,
}

struct PtyProcess {
    pub pty: Pty,
    pub child: ylongChild,
}

impl PtyProcess {
    fn new(pty: Pty, child: ylongChild) -> Self {
        Self {
            pty,
            child,
        }
    }
}

fn init_pty_process(cmd: Option<String>) -> io::Result<PtyProcess> {
    let pty = Pty::new().unwrap();
    let pts = pty.pts().unwrap();
    pty.resize(24, 80, 0, 0).expect("resize set fail");

    let child = match cmd {
        None => {
            let mut command = PtyCommand::new(SHELL_PROG);
            command.spawn(&pts).unwrap()
        }
        Some(cmd) => {
            let trimed = cmd.trim_matches('"');
            let params = ["-c", trimed].to_vec();
            let mut proc = PtyCommand::new(SHELL_PROG);
            let command = proc.args(params);
            command.spawn(&pts).unwrap()
        }
    };
    Ok(PtyProcess::new(pty, child))
}

async fn subprocess_task(
    cmd: Option<String>,
    session_id: u32,
    channel_id: u32,
    ret_command: HdcCommand,
    mut rx: mpsc::BoundedReceiver<Vec<u8>>,
) {
    let mut pty_process = init_pty_process(cmd).unwrap();
    let mut buf = [0_u8; 30720];

    loop {
        ylong_runtime::select!{
            read_res = pty_process.pty.read(&mut buf) => {
                match read_res {
                    Ok(bytes) => {
                        let message = TaskMessage {
                            channel_id,
                            command: ret_command,
                            payload: buf[..bytes].to_vec(),
                        };
                        hdc::trace!("read {bytes} bytes from pty, buf is {:?}", buf);
                        transfer::put(session_id, message).await;
                    }
                    Err(e) => {
                        hdc::warn!("pty read failed: {e:?}");
                        break;
                    }
                }
            },

            recv_res = rx.recv() => {
                match recv_res {
                    Ok(val) =>  { hdc::trace!("recv {:?}:{:?}", channel_id, val);
                        pty_process.pty.write_all(&val).await.unwrap();
                        if val[..].contains(&0x4_u8) {
                            // ctrl-D: end pty
                            hdc::info!("ctrl-D: end pty");
                            break;
                        }
                    }
                    Err(e) => {hdc::debug!("recv_timeout failed: {e:?}");}
                }
            },

            waitchild_res = pty_process.child.wait() => {
                match waitchild_res {
                    Ok(_) => {
                        hdc::debug!("interactive shell finish a process");
                        // break;
                    }
                    Err(e) => {
                        hdc::error!("interactive shell wait failed: {e:?}");
                        break;
                    }
                }
            }
        }
    }
    let message = TaskMessage {
        channel_id,
        command: HdcCommand::KernelChannelClose,
        payload: vec![1],
    };
    transfer::put(session_id, message).await;
    PtyMap::del(channel_id).await;
}

impl PtyTask {
    pub fn new(
        session_id: u32,
        channel_id: u32,
        cmd: Option<String>,
        ret_command: HdcCommand,
    ) -> Self {
        let (tx, rx) = ylong_runtime::sync::mpsc::bounded_channel::<Vec<u8>>(16);
        let handle = ylong_runtime::spawn(subprocess_task(
            cmd,
            session_id,
            channel_id,
            ret_command,
            rx,
        ));
        Self { handle, tx }
    }
}

type PtyMap_ = Arc<Mutex<HashMap<u32, Arc<PtyTask>>>>;
pub struct PtyMap {}
impl PtyMap {
    fn get_instance() -> PtyMap_ {
        static mut PTY_MAP: Option<PtyMap_> = None;
        unsafe {
            PTY_MAP
                .get_or_insert_with(|| Arc::new(Mutex::new(HashMap::new())))
                .clone()
        }
    }

    pub async fn get(channel_id: u32) -> Option<Arc<PtyTask>> {
        let pty_map = Self::get_instance();
        let map = pty_map.lock().unwrap();
        if let Some(pty_task) = map.get(&channel_id) {
            return Some(pty_task.clone());
        }
        None
    }

    pub async fn put(channel_id: u32, pty_task: PtyTask) {
        let pty_map = Self::get_instance();
        let mut map = pty_map.lock().unwrap();
        let arc_pty_task = Arc::new(pty_task);
        map.insert(channel_id, arc_pty_task);
    }

    pub async fn del(channel_id: u32) {
        let pty_map = Self::get_instance();
        let mut map = pty_map.lock().unwrap();
        map.remove(&channel_id);
        let file_name = format!("{SHELL_TEMP}-{channel_id}");
        let _ = std::fs::remove_file(file_name);
    }
}
