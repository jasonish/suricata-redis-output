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

// FFI helpers. This will be removed when these helpers get added to the
// Suricata rust code (where they belong).
mod ffi;

use redis::Commands;
use std::os::raw::{c_char, c_int, c_void};
use std::str::FromStr;
use std::sync::mpsc::TrySendError;
use std::thread;
use std::time::Duration;
use suricata::conf::ConfNode;
use suricata::{SCLogError, SCLogNotice};

// Default configuration values.
const DEFAULT_HOST: &str = "127.0.0.1";
const DEFAULT_PORT: &str = "6379";
const DEFAULT_KEY: &str = "suricata";
const DEFAULT_MODE: &str = "lpush";
const DEFAULT_BUFFER_SIZE: &str = "1000";

// Default timeout for connect/read/write.
const DEFAULT_TIMEOUT: u64 = 6;

#[derive(Debug, Clone)]
enum Mode {
    // Left push (aka list), the default.
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
            port,
            key: key.into(),
            mode,
            buffer: buffer_size,
        };
        Ok(config)
    }
}
struct Redis {
    client: redis::Client,
    config: Config,
    rx: std::sync::mpsc::Receiver<String>,
    count: usize,
}

impl Redis {
    fn new(
        config: Config,
        rx: std::sync::mpsc::Receiver<String>,
    ) -> Result<Self, redis::RedisError> {
        let uri = format!("redis://{}:{}", config.server, config.port);
        let client = redis::Client::open(uri)?;
        Ok(Self {
            config,
            client,
            rx,
            count: 0,
        })
    }

    fn open_connection(&self) -> Result<redis::Connection, redis::RedisError> {
        let timeout = std::time::Duration::from_secs(DEFAULT_TIMEOUT);
        let conn = self.client.get_connection_with_timeout(timeout)?;
        conn.set_read_timeout(Some(timeout))?;
        conn.set_write_timeout(Some(timeout))?;
        Ok(conn)
    }

    fn submit(
        &self,
        connection: &mut redis::Connection,
        buf: &str,
    ) -> Result<u32, redis::RedisError> {
        match self.config.mode {
            Mode::Lpush => connection.lpush(&self.config.key, buf),
            Mode::Rpush => connection.rpush(&self.config.key, buf),
            Mode::Publish => connection.publish(&self.config.key, buf),
        }
    }

    fn run(&mut self) {
        // Get a peekable iterator from the incoming channel. This allows us to
        // get the next message from the channel without removing it, we can
        // then remove it once its been sent to the server without error.
        //
        // Not sure how this will work with pipe-lining tho, will probably have
        // to do some buffering here, or just accept that any log records
        // in-flight will be lost.
        let mut iter = self.rx.iter().peekable();
        'connection: loop {
            SCLogNotice!("Opening Redis connection");
            let mut connection = match self.open_connection() {
                Err(err) => {
                    SCLogError!("Failed to open Redis connection: {:?}", err);
                    thread::sleep(Duration::from_secs(DEFAULT_TIMEOUT));
                    continue;
                }
                Ok(connection) => connection,
            };
            SCLogNotice!("Redis conneciton opened");

            loop {
                if let Some(buf) = iter.peek() {
                    self.count += 1;
                    if let Err(err) = self.submit(&mut connection, buf) {
                        SCLogError!("Failed to send event to Redis: {:?}", err);
                        break;
                    } else {
                        // Successfully sent.  Pop it off the channel.
                        let _ = iter.next();
                    }
                } else {
                    break 'connection;
                }
            }
        }
        SCLogNotice!("Redis connecton finished: count={}", self.count,);
    }
}

struct Context {
    tx: std::sync::mpsc::SyncSender<String>,
    count: usize,
    dropped: usize,
}

unsafe extern "C" fn output_init(
    conf: *const c_void,
    threaded: bool,
    init_data: *mut *mut c_void,
) -> c_int {
    if threaded {
        SCLogError!("This Redis output plugin does not support threaded EVE yet");
        panic!()
    }

    // Load configuration.
    let config = if conf.is_null() {
        Config::default()
    } else {
        Config::new(&ConfNode::wrap(conf)).unwrap()
    };

    let (tx, rx) = std::sync::mpsc::sync_channel(config.buffer);

    let mut redis_client = match Redis::new(config, rx) {
        Ok(client) => client,
        Err(err) => {
            SCLogError!("Failed to initialize Redis client: {:?}", err);
            panic!()
        }
    };

    let context = Context {
        tx,
        count: 0,
        dropped: 0,
    };
    std::thread::spawn(move || redis_client.run());

    *init_data = Box::into_raw(Box::new(context)) as *mut _;
    0
}

unsafe extern "C" fn output_close(init_data: *const c_void) {
    let context = Box::from_raw(init_data as *mut Context);
    SCLogNotice!(
        "Redis output finished: count={}, dropped={}",
        context.count,
        context.dropped
    );
    std::mem::drop(context);
}

unsafe extern "C" fn output_write(
    buffer: *const c_char,
    buffer_len: c_int,
    init_data: *const c_void,
    _thread_data: *const c_void,
) -> c_int {
    let context = &mut *(init_data as *mut Context);
    let buf = if let Ok(buf) = ffi::str_from_c_parts(buffer, buffer_len) {
        buf
    } else {
        return -1;
    };

    context.count += 1;

    if let Err(err) = context.tx.try_send(buf.to_string()) {
        context.dropped += 1;
        match err {
            TrySendError::Full(_) => {
                SCLogError!("Eve record lost due to full buffer");
            }
            TrySendError::Disconnected(_) => {
                SCLogError!("Eve record lost due to broken channel");
            }
        }
    }
    0
}

// Not used yet.
unsafe extern "C" fn output_thread_init(
    _init_data: *const c_void,
    _thread_id: std::os::raw::c_int,
    _thread_data: *mut *mut c_void,
) -> c_int {
    0
}

// Not used yet.
unsafe extern "C" fn output_thread_deinit(_init_data: *const c_void, _thread_data: *mut c_void) {}

unsafe extern "C" fn init_plugin() {
    let file_type = ffi::SCEveFileType::new(
        "eve-redis-plugin",
        output_init,
        output_close,
        output_write,
        output_thread_init,
        output_thread_deinit,
    );
    ffi::SCRegisterEveFileType(file_type);
}

#[no_mangle]
extern "C" fn SCPluginRegister() -> *const ffi::SCPlugin {
    // Rust plugins need to initialize some Suricata internals so stuff like logging works.
    suricata::plugin::init();

    // Register our plugin.
    ffi::SCPlugin::new("Redis Eve Filetype", "GPL-2.0", "Jason Ish", init_plugin)
}
