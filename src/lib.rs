// Copyright (c) 2021 Open Information Security Foundation
//
// Permission is hereby granted, free of charge, to any person
// obtaining a copy of this software and associated documentation
// files (the "Software"), to deal in the Software without
// restriction, including without limitation the rights to use, copy,
// modify, merge, publish, distribute, sublicense, and/or sell copies
// of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
// WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

#![allow(clippy::needless_return)]
#![allow(clippy::redundant_field_names)]
mod ffi;

use redis::Commands;
use std::os::raw::{c_char, c_int, c_void};
use std::str::FromStr;
use std::sync::mpsc::TrySendError;
use std::sync::Mutex;
use suricata::conf::ConfNode;
use suricata::SCLogError;

const DEFAULT_HOST: &str = "127.0.0.1";
const DEFAULT_PORT: &str = "6379";
const DEFAULT_KEY: &str = "suricata";
const DEFAULT_MODE: &str = "lpush";
const DEFAULT_BUFFER_SIZE: &str = "1000";

#[derive(Debug, Clone)]
enum Mode {
    // Left push (also list)
    Lpush,
    // Right push
    Rpush,
    // Publish (or channel)
    Publish,
}

impl FromStr for Mode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_ref() {
            "lpush" | "list" => Ok(Self::Lpush),
            "rpush" => Ok(Self::Rpush),
            "publish" | "channel" => Ok(Self::Publish),
            _ => anyhow::bail!("invalid mode"),
        }
    }
}

#[derive(Debug, Clone)]
struct Config {
    server: String,
    port: u16,
    key: String,
    mode: Mode,
    buffer: usize,
}

impl Config {
    fn new(conf: &ConfNode) -> anyhow::Result<Self> {
        let server = conf.get_child_value("server").unwrap_or(DEFAULT_HOST);
        let port = match conf
            .get_child_value("port")
            .unwrap_or(DEFAULT_PORT)
            .parse::<u16>()
        {
            Ok(port) => port,
            Err(_) => anyhow::bail!("invalid port"),
        };
        let buffer_size = match conf
            .get_child_value("buffer-size")
            .unwrap_or(DEFAULT_BUFFER_SIZE)
            .parse::<usize>()
        {
            Ok(size) => size,
            Err(_) => anyhow::bail!("invalid buffer-size"),
        };

        let key = conf.get_child_value("key").unwrap_or(DEFAULT_KEY);
        let mode = Mode::from_str(conf.get_child_value("mode").unwrap_or(DEFAULT_MODE))?;
        let config = Config {
            server: server.into(),
            port: port,
            key: key.into(),
            mode: mode,
            buffer: buffer_size,
        };
        Ok(config)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: DEFAULT_HOST.into(),
            port: DEFAULT_PORT.parse().unwrap(),
            buffer: DEFAULT_PORT.parse().unwrap(),
            key: DEFAULT_KEY.into(),
            mode: Mode::from_str(DEFAULT_MODE).unwrap(),
        }
    }
}

// The writer is what sends the Eve records to Redis and maintains the connection to Redis.
//
// The writer runs in its own thread waiting on a channel for new records to send to Redis.
struct Writer {
    config: Config,
    client: redis::Client,
    rx: std::sync::mpsc::Receiver<String>,
}

impl Writer {
    fn new(config: Config, rx: std::sync::mpsc::Receiver<String>) -> anyhow::Result<Self> {
        let uri = format!("redis://{}:{}", config.server, config.port);
        let client = redis::Client::open(uri)?;
        Ok(Self { config, client, rx })
    }

    fn run(&mut self) {
        // TODO: Enter reconnection loop on start in case Redis isn't ready. Also, on write
        //  error, re-enter reconnection loop.
        let mut conn = self.client.get_connection().unwrap();
        loop {
            let record = match self.rx.recv() {
                Ok(record) => record,
                Err(_) => {
                    // This will only happen if the sending side of our channel is closed, which
                    // happens on shutdown which is our notification to stop this loop.
                    return;
                }
            };
            if let Err(err) = self.write(&mut conn, &record) {
                SCLogError!("Failed to write eve record to Redis: {}", err);
            }
        }

        // We should never get here. If we exit the loop the sending side will fail and panic.
        #[allow(unreachable_code)]
        {
            panic!("entered unreachable code: code error");
        }
    }

    fn write(
        &mut self,
        conn: &mut redis::Connection,
        record: &str,
    ) -> Result<u32, redis::RedisError> {
        match self.config.mode {
            Mode::Lpush => conn.lpush(&self.config.key, record),
            Mode::Rpush => conn.rpush(&self.config.key, record),
            Mode::Publish => conn.publish(&self.config.key, record),
        }
    }
}

struct FileType {
    tx: Mutex<std::sync::mpsc::SyncSender<String>>,
}

impl FileType {
    fn write(&self, record: &str) -> Result<(), TrySendError<String>> {
        // When not in threaded we may still be called from multiple threads, so we have to take
        // care of locking ourselves.
        let tx = self.tx.lock().unwrap();
        tx.try_send(record.to_string())
    }
}

unsafe extern "C" fn do_write(
    buffer: *const c_char,
    buffer_len: c_int,
    init_data: *const c_void,
    thread_data: *const c_void,
) -> c_int {
    let init_data = &mut *(init_data as *mut FileType);
    let thread_state = if thread_data.is_null() {
        None
    } else {
        Some(&mut *(thread_data as *mut ThreadState))
    };

    let buf = if let Ok(buf) = ffi::str_from_c_parts(buffer, buffer_len) {
        buf
    } else {
        return -1;
    };

    let result = if let Some(thread_state) = thread_state {
        thread_state.write(buf)
    } else {
        init_data.write(buf)
    };
    match result {
        Err(TrySendError::Disconnected(_)) => {
            // The thread the sends messages to Redis has crashed. This is an unrecoverable error.
            panic!("Failed to send Eve record to Redis writer channel: disconnected");
        }
        Err(TrySendError::Full(_)) => {
            // The internal buffer is full.
            //
            // TODO: Some rate limited error logging would be useful here.
            SCLogError!("Redis channel full, event record lost");
            return -1;
        }
        Ok(_) => {
            return 0;
        }
    }
}

unsafe extern "C" fn init_filetype(
    conf: *const c_void,
    _threaded: bool,
    init_data: *mut *mut c_void,
) -> c_int {
    let config = if let Some(config) = ConfNode::wrap(conf).get_child("redis") {
        Config::new(&config).unwrap()
    } else {
        Config::default()
    };

    let (tx, rx) = std::sync::mpsc::sync_channel::<String>(1000);
    let data = FileType { tx: Mutex::new(tx) };
    let x = Box::into_raw(Box::new(data));
    *init_data = x as *mut c_void;

    let mut writer = Writer::new(config, rx).unwrap();
    std::thread::spawn(move || {
        writer.run();
    });

    return 0;
}

// Deinitialize, or "close" this file type. As this is Rust, we just take back ownership of the
// FileType and drop it.
extern "C" fn deinit_filetype(init_data: *const c_void) {
    unsafe {
        let filetype = &mut *(init_data as *mut FileType);
        let filetype: Box<FileType> = Box::from_raw(filetype);
        std::mem::drop(filetype);
    }
}

struct ThreadState {
    tx: std::sync::mpsc::SyncSender<String>,
}

impl ThreadState {
    fn write(&self, record: &str) -> Result<(), TrySendError<String>> {
        // Unlike the writer on the FileType we do not need to lock here and Suricata ensures
        // only one write per thread.
        //self.tx.send(record.to_string())
        self.tx.try_send(record.to_string())
    }
}

unsafe extern "C" fn thread_init(
    init_data: *const c_void,
    _thread_id: c_int,
    thread_data: *mut *mut c_void,
) -> c_int {
    let file_type = &*(init_data as *const FileType);
    let tx = file_type.tx.lock().unwrap().clone();
    let thread_state = ThreadState { tx };
    *thread_data = Box::into_raw(Box::new(thread_state)) as *mut c_void;
    return 0;
}

unsafe extern "C" fn thread_deinit(_init_data: *const c_void, thread_data: *const c_void) {
    let thread_state = &mut *(thread_data as *mut ThreadState);
    let thread_state: Box<ThreadState> = Box::from_raw(thread_state);
    std::mem::drop(thread_state);
}

// Plugin initialization. This is called by Suricata after receiving the plugin declaration. Here
// we register a new Eve file type.
unsafe extern "C" fn init_plugin() {
    let file_type = ffi::SCEveFileType::new(
        "rust-redis",
        init_filetype,
        Some(deinit_filetype),
        Some(thread_init),
        Some(thread_deinit),
        Some(do_write),
    );
    ffi::SCRegisterEveFileType(file_type);
}

// Register's this module as a plugin. This is the function that Suricata will look for after
// loading the plugin.
#[no_mangle]
extern "C" fn SCPluginRegister() -> *const ffi::SCPlugin {
    // Some necessary bootstrapping of the Rust address space.
    suricata::plugin::init();

    // Return our plugin declaration.
    ffi::SCPlugin::new("Redis Eve Filetype", "GPL-2.0", "Jason Ish", init_plugin)
}
