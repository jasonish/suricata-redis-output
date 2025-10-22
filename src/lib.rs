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
use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;
use suricata::conf::ConfNode;
use suricata::{SCLogError, SCLogNotice};
use suricata_sys::sys::SCConfNode;
use suricata_sys::sys::{SCPlugin, SC_API_VERSION, SC_PACKAGE_VERSION};

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
    done: Arc<AtomicBool>,
}

impl Redis {
    fn new(
        config: Config,
        rx: std::sync::mpsc::Receiver<String>,
        done: Arc<AtomicBool>,
    ) -> Result<Self, redis::RedisError> {
        let uri = format!("redis://{}:{}", config.server, config.port);
        let client = redis::Client::open(uri)?;
        Ok(Self {
            config,
            client,
            rx,
            count: 0,
            done,
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
        'connection: while !self.done.load(Ordering::Relaxed) {
            SCLogNotice!("Opening Redis connection");
            let mut connection = match self.open_connection() {
                Err(err) => {
                    SCLogError!("Failed to open Redis connection: {:?}", err);
                    // Check if we're done. This is required to exit cleanly if we exit
                    // while in the reconnect loop.
                    if self.done.load(Ordering::Relaxed) {
                        break;
                    }
                    thread::sleep(Duration::from_secs(DEFAULT_TIMEOUT));
                    continue;
                }
                Ok(connection) => connection,
            };
            SCLogNotice!("Redis conneciton opened");

            while let Some(buf) = iter.peek() {
                self.count += 1;
                if let Err(err) = self.submit(&mut connection, buf) {
                    SCLogError!("Failed to send event to Redis: {:?}", err);
                    continue 'connection;
                }
                let _ = iter.next();
            }

            // Incoming channel has been closed, we must have entered shutdown.
            break;
        }

        // Count how many events are lost. This should only happen if Suricata
        // was told to exit while the Redis output was in a reconnecting mode.
        let mut lost = 0;
        while self.rx.try_recv().is_ok() {
            lost += 1;
        }

        SCLogNotice!(
            "Redis connecton finished: count={}, lost={}",
            self.count,
            lost
        );
    }
}

struct Context {
    tx: SyncSender<String>,
    th: JoinHandle<()>,
    done: Arc<AtomicBool>,
}

struct ThreadContext {
    thread_id: usize,
    tx: SyncSender<String>,
    count: usize,
    dropped: usize,
}

impl ThreadContext {
    fn new(thread_id: usize, tx: SyncSender<String>) -> Self {
        Self {
            thread_id,
            tx,
            count: 0,
            dropped: 0,
        }
    }

    fn send(&mut self, buf: &str) {
        self.count += 1;
        if let Err(err) = self.tx.try_send(buf.to_string()) {
            self.dropped += 1;
            match err {
                TrySendError::Full(_) => {
                    SCLogError!("Eve record lost due to full buffer");
                }
                TrySendError::Disconnected(_) => {
                    SCLogError!("Eve record lost due to broken channel");
                }
            }
        }
    }

    fn log_exit_stats(&self) {
        SCLogNotice!(
            "Redis output finished: thread={}, count={}, dropped={}",
            self.thread_id,
            self.count,
            self.dropped
        );
    }
}

unsafe extern "C" fn output_init(
    conf: *const c_void,
    _threaded: bool,
    init_data: *mut *mut c_void,
) -> c_int {
    // Load configuration.
    let config = if conf.is_null() {
        Config::default()
    } else {
        ConfNode::wrap(conf as *const SCConfNode)
            .get_child_node("redis")
            .map(|conf| Config::new(&conf).unwrap())
            .unwrap_or_default()
    };

    let (tx, rx) = std::sync::mpsc::sync_channel(config.buffer);
    let done = Arc::new(AtomicBool::new(false));

    let mut redis_client = match Redis::new(config, rx, done.clone()) {
        Ok(client) => client,
        Err(err) => {
            SCLogError!("Failed to initialize Redis client: {:?}", err);
            panic!()
        }
    };

    let th = std::thread::spawn(move || redis_client.run());
    let context = Context {
        tx: tx.clone(),
        th,
        done,
    };

    *init_data = Box::into_raw(Box::new(context)) as *mut _;
    0
}

unsafe extern "C" fn output_close(init_data: *const c_void) {
    let context = Box::from_raw(init_data as *mut Context);
    context.done.store(true, Ordering::Relaxed);

    // Need to drop the transmit side of the channel before waiting for the
    // Redis thread to finish.
    std::mem::drop(context.tx);

    // Wait for Redis thread to finish.
    let _ = context.th.join();
}

unsafe extern "C" fn output_write(
    buffer: *const c_char,
    buffer_len: c_int,
    _init_data: *const c_void,
    thread_data: *const c_void,
) -> c_int {
    // If thread_data is null then we're setup for single threaded mode, and use
    // the default thread context.
    let thread_context = &mut *(thread_data as *mut ThreadContext);

    // Convert the C string to a Rust string.
    let buf = if let Ok(buf) = ffi::str_from_c_parts(buffer, buffer_len) {
        buf
    } else {
        return -1;
    };

    thread_context.send(buf);
    0
}

unsafe extern "C" fn output_thread_init(
    init_data: *const c_void,
    thread_id: std::os::raw::c_int,
    thread_data: *mut *mut c_void,
) -> c_int {
    let context = &mut *(init_data as *mut Context);
    let thread_context = ThreadContext::new(thread_id as usize, context.tx.clone());
    *thread_data = Box::into_raw(Box::new(thread_context)) as *mut _;
    0
}

unsafe extern "C" fn output_thread_deinit(_init_data: *const c_void, thread_data: *mut c_void) {
    let thread_context = Box::from_raw(thread_data as *mut ThreadContext);
    thread_context.log_exit_stats();
    std::mem::drop(thread_context);
}

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
extern "C" fn SCPluginRegister() -> *const SCPlugin {
    suricata::plugin::init();

    let plugin_version =
        CString::new(env!("CARGO_PKG_VERSION")).unwrap().into_raw() as *const c_char;
    let plugin = SCPlugin {
        version: SC_API_VERSION,
        suricata_version: SC_PACKAGE_VERSION.as_ptr() as *const c_char,
        name: b"redis-output\0".as_ptr() as *const c_char,
        plugin_version,
        license: b"MIT\0".as_ptr() as *const c_char,
        author: b"Jason Ish\0".as_ptr() as *const c_char,
        Init: Some(init_plugin),
    };
    Box::into_raw(Box::new(plugin))
}
