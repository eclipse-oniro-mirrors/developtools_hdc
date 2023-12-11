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
//! auth
#![allow(missing_docs)]

use hdc::config::{self, *};
use hdc::serializer::native_struct;
use hdc::serializer::serialize::Serialization;
use hdc::transfer;

use openssl::base64;
use openssl::rsa::{Padding, Rsa};
use ylong_runtime::sync::RwLock;

use crate::utils::hdc_log::*;
use std::fs::File;
use std::collections::HashMap;
use std::io::{self, Error, ErrorKind, Write, prelude::*};
use std::path::Path;
use std::sync::Arc;
// use std::process::Command;
use std::string::ToString;
use super::sys_para::{*};

#[derive(Clone, PartialEq, Eq)]
pub enum AuthStatus {
    Init(String),           // with plain
    Pubk((String, String)), // with (plain, pk)
    Ok,
    Fail,
}

pub enum UserPermit {
    Refuse = 0,
    AllowOnce = 1,
    AllowForever = 2,
    Cancel = 3,
    Invalid = 5,
}

type AuthStatusMap_ = Arc<RwLock<HashMap<u32, AuthStatus>>>;

pub struct AuthStatusMap {}
impl AuthStatusMap {
    fn get_instance() -> AuthStatusMap_ {
        static mut AUTH_STATUS_MAP: Option<AuthStatusMap_> = None;
        unsafe {
            AUTH_STATUS_MAP
                .get_or_insert_with(|| Arc::new(RwLock::new(HashMap::new())))
                .clone()
        }
    }

    pub async fn get(session_id: u32) -> AuthStatus {
        let instance = Self::get_instance();
        let map = instance.read().await;
        map.get(&session_id).unwrap().clone()
    }

    async fn put(session_id: u32, auth_status: AuthStatus) {
        let instance = Self::get_instance();
        let mut map = instance.write().await;
        map.insert(session_id, auth_status);
    }
}

pub async fn handshake_init(task_message: TaskMessage) -> io::Result<(u32, TaskMessage)> {
    if task_message.command != HdcCommand::KernelHandshake {
        return Err(Error::new(ErrorKind::Other, "unknown command flag"));
    }

    let mut recv = native_struct::SessionHandShake::default();
    recv.parse(task_message.payload)?;

    hdc::info!("recv handshake: {:#?}", recv);
    if recv.banner != HANDSHAKE_MESSAGE {
        return Err(Error::new(ErrorKind::Other, "Recv server-hello failed"));
    }

    if recv.version.as_str() < "Ver: 1.3.1" {
        hdc::info!("client version({}) is too low, return OK for session:{}", recv.version.as_str(), recv.session_id);
        return Ok((
            recv.session_id,
            make_ok_message(recv.session_id, task_message.channel_id).await,
        ));
    }
    if !is_auth_enable().await {
        hdc::info!("auth enable is false, return OK for session:{}", recv.session_id);
        return Ok((
            recv.session_id,
            make_ok_message(recv.session_id, task_message.channel_id).await,
        ));
    }

    // auth is required
    let buf = generate_token_wait().await;

    AuthStatusMap::put(recv.session_id, AuthStatus::Init(buf.clone())).await;

    let send = native_struct::SessionHandShake {
        banner: HANDSHAKE_MESSAGE.to_string(),
        session_id: recv.session_id,
        connect_key: "".to_string(),
        buf,
        auth_type: AuthType::Publickey as u8,
        version: get_version(),
    };

    hdc::info!("send handshake: {:#?}", send);
    let message = TaskMessage {
        channel_id: task_message.channel_id,
        command: HdcCommand::KernelHandshake,
        payload: send.serialize(),
    };
    Ok((recv.session_id, message))
}

async fn make_sign_message(session_id: u32, token: String, channel_id: u32) -> TaskMessage {
    let send = native_struct::SessionHandShake {
        banner: HANDSHAKE_MESSAGE.to_string(),
        session_id,
        connect_key: "".to_string(),
        buf: token,
        auth_type: AuthType::Signature as u8,
        version: get_version(),
    };
    TaskMessage {
        channel_id,
        command: HdcCommand::KernelHandshake,
        payload: send.serialize(),
    }
}

async fn make_ok_message(session_id: u32, channel_id: u32) -> TaskMessage {
    AuthStatusMap::put(session_id, AuthStatus::Ok).await;

    let send = native_struct::SessionHandShake {
        banner: HANDSHAKE_MESSAGE.to_string(),
        session_id,
        connect_key: "".to_string(),
        auth_type: AuthType::OK as u8,
        version: get_version(),
        buf: match nix::unistd::gethostname() {
            Ok(hostname) => hostname.into_string().unwrap(),
            Err(_) => String::from("unknown"),
        },
    };
    TaskMessage {
        channel_id,
        command: HdcCommand::KernelHandshake,
        payload: send.serialize(),
    }
}

pub fn get_host_pubkey_info(buf: &str) -> (String, String) {
    if let Some((hostname, pubkey)) = buf.split_once(HDC_HOST_DAEMON_BUF_SEPARATOR) {
        (hostname.to_string(), pubkey.to_string())
    } else {
        ("".to_string(), "".to_string())
    }
}

pub async fn handshake_task(task_message: TaskMessage, session_id: u32) -> io::Result<()> {
    let mut recv = native_struct::SessionHandShake::default();
    recv.parse(task_message.payload)?;

    let channel_id = task_message.channel_id;

    if recv.auth_type == AuthType::Publickey as u8 {
        let plain = if let AuthStatus::Init(buf) = AuthStatusMap::get(session_id).await {
            buf
        } else {
            handshake_fail(session_id, channel_id, "auth failed".to_string()).await;
            return Ok(());
        };
        let token = plain.clone();

        let (hostname, pubkey) = get_host_pubkey_info(recv.buf.trim());
        if pubkey.is_empty() {
            hdc::error!("get public key from host failed");
            handshake_fail(session_id, channel_id, "no public key, you may need update your hdc client".to_string()).await;
            return Ok(())
        }
        if hostname.is_empty() {
            hdc::error!("get hostname from host failed");
            handshake_fail(session_id, channel_id, "no hostname, you may need update your hdc client".to_string()).await;
            return Ok(())
        }

        let known_hosts = read_known_hosts_pubkey();
        if known_hosts.contains(&pubkey) {
            hdc::info!("pubkey matches known host({})", hostname);
            AuthStatusMap::put(session_id, AuthStatus::Pubk((plain, pubkey))).await;
            transfer::put(session_id, make_sign_message(session_id, token, channel_id).await).await;
            return Ok(());
        }
        match require_user_permittion(&hostname).await {
            UserPermit::AllowForever => {
                hdc::info!("allow forever");
                if write_known_hosts_pubkey(&pubkey).is_err() {
                    handshake_fail(session_id, channel_id, "write public key failed".to_string()).await;

                    hdc::error!("write public key failed");
                    return Ok(());
                }
                AuthStatusMap::put(session_id, AuthStatus::Pubk((plain, pubkey))).await;
                transfer::put(session_id, make_sign_message(session_id, token, channel_id).await).await;
            },
            UserPermit::AllowOnce => {
                hdc::info!("allow once");
                AuthStatusMap::put(session_id, AuthStatus::Pubk((plain, pubkey))).await;
                transfer::put(session_id, make_sign_message(session_id, token, channel_id).await).await;
            },
            _ =>  {
                hdc::info!("user refuse");
                handshake_fail(session_id, channel_id, "public key refused by device".to_string()).await;
                return Ok(());
            }
        }
    } else if recv.auth_type == AuthType::Signature as u8 {
        match validate_signature(recv.buf, session_id).await {
            Ok(()) => {
                transfer::put(session_id, make_ok_message(session_id, channel_id).await).await;
                transfer::put(
                    session_id,
                    TaskMessage {
                        channel_id,
                        command: HdcCommand::KernelChannelClose,
                        payload: vec![0],
                    },
                )
                .await;
                AuthStatusMap::put(session_id, AuthStatus::Ok).await;
            }
            Err(e) => {
                let errlog = e.to_string();
                hdc::error!("validate signature failed: {}", &errlog);
                handshake_fail(session_id, channel_id, errlog).await;
            }
        }
    } else {
        handshake_fail(session_id, channel_id, "auth failed".to_string()).await;
    }
    Ok(())
}

async fn validate_signature(signature: String, session_id: u32) -> io::Result<()> {
    let (plain, pubkey) =
        if let AuthStatus::Pubk((plain, pubkey)) = AuthStatusMap::get(session_id).await {
            (plain, pubkey)
        } else {
            return Err(Error::new(ErrorKind::Other, "auth failed"));
        };

    let signature_bytes = if let Ok(bytes) = base64::decode_block(&signature) {
        bytes
    } else {
        return Err(Error::new(ErrorKind::Other, "signature decode failed"));
    };

    let rsa = if let Ok(cipher) = Rsa::public_key_from_pem(pubkey.as_bytes()) {
        cipher
    } else {
        return Err(Error::new(ErrorKind::Other, "pubkey convert failed"));
    };

    let mut buf = vec![0_u8; config::RSA_BIT_NUM];
    let dec_size = rsa
        .public_decrypt(&signature_bytes, &mut buf, Padding::PKCS1)
        .unwrap_or(0);

    if plain.as_bytes() == &buf[..dec_size] {
        Ok(())
    } else {
        Err(Error::new(ErrorKind::Other, "signature not match"))
    }
}

fn read_known_hosts_pubkey() -> Vec<String> {
    let file_name = Path::new(config::RSA_PUBKEY_PATH).join(config::RSA_PUBKEY_NAME);
    if let Ok(keys) = std::fs::read_to_string(&file_name) {
        let mut key_vec = vec![];
        let mut tmp_vec = vec![];

        for line in keys.split('\n') {
            if line.contains("BEGIN PUBLIC KEY") {
                tmp_vec.clear();
            }
            tmp_vec.push(line);
            if line.contains("END PUBLIC KEY") {
                key_vec.push(tmp_vec.join("\n"));
            }
        }

        hdc::debug!("read {} known hosts from file", key_vec.len());
        key_vec
    } else {
        hdc::info!("pubkey file {:#?} not exists", file_name);
        vec![]
    }
}

fn write_known_hosts_pubkey(pubkey: &String) -> io::Result<()> {
    let file_name = Path::new(config::RSA_PUBKEY_PATH).join(config::RSA_PUBKEY_NAME);
    if !file_name.exists() {
        hdc::info!("create pubkeys file at {:#?}", file_name);
        let _ = std::fs::create_dir_all(config::RSA_PUBKEY_PATH);
        let _ = std::fs::File::create(&file_name).unwrap();
    }

    let _ = match std::fs::File::options().append(true).open(file_name) {
        Ok(mut f) => writeln!(&mut f, "{}", pubkey),
        Err(e) => {
            hdc::error!("write pubkey err: {e}");
            return Err(e);
        }
    };
    Ok(())
}

fn call_setting_ability() -> bool {
    true
}

pub async fn is_auth_enable() -> bool {
    // match get_dev_item("const.secure", "1") {
    //     (false, _) => true,
    //     (true, auth_enable) => auth_enable.trim().to_lowercase() == "1",
    // }
    true
}

pub async fn auth_cancel_monitor() {
    if !is_auth_enable().await {
        hdc::error!("auth is not enable");
        return;
    }

    loop {
        // clear result first
        if !set_dev_item("rw.hdc.daemon.auth_result", (UserPermit::Invalid as u32).to_string().as_str()) {
            hdc::error!("clear param failed.");
            continue;
        }
        if !wait_dev_item("rw.hdc.daemon.auth_result", "auth_cancel:*", HDC_WAIT_PARAMETER_FOREVER) {
            continue;
        }
        match get_dev_item("rw.hdc.daemon.auth_result", "_") {
            (false, _) => continue,
            (true, cancel_result) => {
                if cancel_result.strip_prefix("auth_cancel:").unwrap().trim() == (UserPermit::Cancel as u32).to_string() {
                    hdc::error!("user cancel the auth, hdcd will restart now.");
                    // must clear the auth_result, otherwise next auth cancel will fail
                    if !set_dev_item("rw.hdc.daemon.auth_cancel", (UserPermit::Invalid as u32).to_string().as_str()) {
                        hdc::error!("clear param failed before restart, next cancel maybe fail.");
                    }
                    // restart my self
                    // hdc_fork();
                }
            }
        }
    }
}

async fn predeal_debug_permit() -> bool {
    let (auth_debug, auth_result) = get_dev_item("rw.hdc.daemon.auth_debug", "_");
    if !auth_debug || auth_result == "_" {
        hdc::info!("not debug auth result");
        return false;
    }

    if !set_dev_item("rw.hdc.daemon.auth_result", auth_result.trim()) {
        hdc::error!("set debug value({}) for auth result failed", auth_result);
        return false;
    }

    if !set_dev_item("rw.hdc.daemon.auth_debug", "_") {
        hdc::error!("set rw.hdc.daemon.auth_debug failed");
    }

    hdc::info!("debug for auth result");

    true
}

async fn require_user_permittion(hostname: &str) -> UserPermit {
    // (UserPermit::Invalid as u32).to_string().as_str();
    // todo: debug for test, release must use invalid as default
    if !predeal_debug_permit().await {
        let default_permit = "auth_result:2";
        // clear result first
        if !set_dev_item("rw.hdc.daemon.auth_result", default_permit) {
            hdc::error!("debug auth result failed, so refuse this connect.");
            return UserPermit::Refuse;
        }
    }
    // then write para for setting
    if !set_dev_item("rw.hdc.client.hostname", hostname) {
        hdc::error!("set param({}) failed.", hostname);
        return UserPermit::Refuse;
    }
    // call setting ability
    if !call_setting_ability() {
        hdc::error!("show dialog failed, so refuse this connect.");
        return UserPermit::Refuse;
    }
    if !wait_dev_item("rw.hdc.daemon.auth_result", "auth_result:*", HDC_WAIT_PARAMETER_FOREVER) {
        hdc::error!("wait for auth result failed, so refuse this connect.");
        return UserPermit::Refuse;
    }
    let permit_result = match get_dev_item("rw.hdc.daemon.auth_result", "_") {
        (false, _) => UserPermit::Refuse,
        (true, auth_result) => {
            match auth_result.strip_prefix("auth_result:").unwrap().trim() {
                "1" => UserPermit::AllowOnce,
                "2" => UserPermit::AllowForever,
                _ => UserPermit::Refuse,
            }
        }
    };
    // clear result at the end for auth_cancel
    if !set_dev_item("rw.hdc.daemon.auth_result", (UserPermit::Invalid as u32).to_string().as_str()) {
        hdc::error!("clear param at the end failed.");
        return UserPermit::Refuse;
    }
    permit_result
}

async fn handshake_fail(session_id: u32, channel_id: u32, msg: String) {
    AuthStatusMap::put(session_id, AuthStatus::Fail).await;
    let send = native_struct::SessionHandShake {
        banner: HANDSHAKE_MESSAGE.to_string(),
        session_id,
        auth_type: AuthType::Fail as u8,
        buf: msg,
        ..Default::default()
    };
    transfer::put(
        session_id,
        TaskMessage {
            channel_id,
            command: config::HdcCommand::KernelHandshake,
            payload: send.serialize(),
        },
    )
    .await;
}

async fn generate_token() -> io::Result<String> {
    let mut random_file = File::open("/dev/random")?;
    let mut buffer = [0; HDC_HANDSHAKE_TOKEN_LEN];
    random_file.read_exact(&mut buffer)?;
    let random_vec: Vec<_> = buffer.iter().map(|h| format!("{:02X}", h)).collect();
    let token = random_vec.join("");
    Ok(token)
}
async fn generate_token_wait() -> String {
    loop {
        match generate_token().await {
            Ok(token) => {
                break token;
            }
            Err(e) => {
                let errlog = e.to_string();
                hdc::error!("generate token failed: {}", &errlog);
            }
        }
    }
}