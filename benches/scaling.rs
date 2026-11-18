//! Multi-core scaling benchmark.
//!
//! Runs a closed-loop workload over loopback TCP with separate client and
//! server runtimes, so the worker thread count of each side can be varied
//! independently. One line of results is printed per run.
//!
//! Configuration is read from the environment:
//!
//! - `LIB`: `http2` (default) or `h2`, the upstream crate, for comparison.
//! - `SCENARIO`: `rpc` (default) or `echo`.
//! - `SERVER_THREADS` / `CLIENT_THREADS`: worker threads, `0` for a
//!   current-thread runtime. Default `1`.
//! - `CONNS`: connections. Default `1`.
//! - `STREAMS`: concurrent streams per connection. Default `64`.
//! - `DURATION_MS`: measured time. Default `3000`.
//! - `REQUESTS`: stop after this many `rpc` requests instead, for runs that
//!   compare a fixed amount of work. Default `0`, for none.
//! - `REQ_BODY` / `RESP_BODY`: body bytes per request. Default `0` / `16`.
//! - `CHUNK`: bytes per `send_data`. Default `16384`.
//! - `WINDOW` / `CONN_WINDOW`: receive windows. Default 1 MiB / 4 MiB.
//! - `ECHO_MSGS`: messages per `echo` stream. Default `64`.
//! - `WORK_US`: CPU time the server spends on each `rpc` request. Default `0`.

use std::{
    error::Error,
    future::poll_fn,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use http::{Request, Response};
use tokio::{
    net::{TcpListener, TcpStream},
    runtime::{Builder, Runtime},
};

type BoxError = Box<dyn Error + Send + Sync>;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Scenario {
    Rpc,
    Echo,
}

#[derive(Clone, Copy, Debug)]
struct Config {
    scenario: Scenario,
    server_threads: usize,
    client_threads: usize,
    conns: usize,
    streams: usize,
    duration: Duration,
    requests: usize,
    req_body: usize,
    resp_body: usize,
    chunk: usize,
    window: u32,
    conn_window: u32,
    echo_msgs: usize,
    work: Duration,
}

#[derive(Default)]
struct Stats {
    ops: u64,
    latencies: Vec<u32>,
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

impl Config {
    fn from_env() -> Self {
        let scenario = match std::env::var("SCENARIO").as_deref() {
            Ok("echo") => Scenario::Echo,
            _ => Scenario::Rpc,
        };

        Config {
            scenario,
            server_threads: env_usize("SERVER_THREADS", 1),
            client_threads: env_usize("CLIENT_THREADS", 1),
            conns: env_usize("CONNS", 1),
            streams: env_usize("STREAMS", 64),
            duration: Duration::from_millis(env_usize("DURATION_MS", 3000) as u64),
            requests: env_usize("REQUESTS", 0),
            req_body: env_usize("REQ_BODY", 0),
            resp_body: env_usize("RESP_BODY", 16),
            chunk: env_usize("CHUNK", 16 * 1024).max(1),
            window: env_usize("WINDOW", 1024 * 1024) as u32,
            conn_window: env_usize("CONN_WINDOW", 4 * 1024 * 1024) as u32,
            echo_msgs: env_usize("ECHO_MSGS", 64),
            work: Duration::from_micros(env_usize("WORK_US", 0) as u64),
        }
    }
}

fn runtime(threads: usize) -> Runtime {
    let mut builder = if threads == 0 {
        Builder::new_current_thread()
    } else {
        let mut builder = Builder::new_multi_thread();
        builder.worker_threads(threads);
        builder
    };
    builder.enable_all().build().unwrap()
}

/// Spends `work` of CPU time, standing in for request handling.
fn burn(work: Duration) {
    if work.is_zero() {
        return;
    }

    let started = Instant::now();
    while started.elapsed() < work {
        std::hint::spin_loop();
    }
}

/// Process CPU time in clock ticks, as `(user, system)`.
fn cpu_ticks() -> (u64, u64) {
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    // Skip past the command name, which may contain spaces.
    let fields: Vec<&str> = stat
        .rsplit_once(')')
        .map(|(_, rest)| rest.split_whitespace().collect())
        .unwrap_or_default();
    let field = |idx: usize| fields.get(idx).and_then(|v| v.parse().ok()).unwrap_or(0);
    (field(11), field(12))
}

/// Voluntary context switches summed over all threads.
fn voluntary_switches() -> u64 {
    let Ok(tasks) = std::fs::read_dir("/proc/self/task") else {
        return 0;
    };

    tasks
        .flatten()
        .filter_map(|task| std::fs::read_to_string(task.path().join("status")).ok())
        .filter_map(|status| {
            status
                .lines()
                .find_map(|line| line.strip_prefix("voluntary_ctxt_switches:"))
                .and_then(|value| value.trim().parse::<u64>().ok())
        })
        .sum()
}

macro_rules! bench_impl {
    ($name:ident, $lib:ident) => {
        mod $name {
            use super::*;
            use $lib::{RecvStream, SendStream, client, server};

            async fn send_body(
                send: &mut SendStream<Bytes>,
                chunk: &Bytes,
                mut remaining: usize,
            ) -> Result<(), BoxError> {
                if remaining == 0 {
                    send.send_data(Bytes::new(), true)?;
                    return Ok(());
                }

                while remaining > 0 {
                    let len = remaining.min(chunk.len());
                    send_chunk(send, chunk.slice(..len), remaining == len).await?;
                    remaining -= len;
                }

                Ok(())
            }

            async fn send_chunk(
                send: &mut SendStream<Bytes>,
                chunk: Bytes,
                end_of_stream: bool,
            ) -> Result<(), BoxError> {
                let len = chunk.len();
                send.reserve_capacity(len);

                while send.capacity() < len {
                    match poll_fn(|cx| send.poll_capacity(cx)).await {
                        Some(Ok(_)) => {}
                        Some(Err(err)) => return Err(err.into()),
                        None => return Err("stream closed while sending".into()),
                    }
                }

                send.send_data(chunk, end_of_stream)?;
                Ok(())
            }

            async fn drain(body: &mut RecvStream) -> Result<usize, BoxError> {
                let mut received = 0;
                while let Some(chunk) = body.data().await {
                    let chunk = chunk?;
                    received += chunk.len();
                    body.flow_control().release_capacity(chunk.len())?;
                }
                Ok(received)
            }

            async fn handle(
                mut request: Request<RecvStream>,
                mut respond: server::SendResponse<Bytes>,
                config: Config,
                chunk: Bytes,
            ) -> Result<(), BoxError> {
                let body = request.body_mut();
                let mut send = respond.send_response(Response::new(()), false)?;

                if config.scenario == Scenario::Echo {
                    while let Some(data) = body.data().await {
                        let data = data?;
                        body.flow_control().release_capacity(data.len())?;
                        send_chunk(&mut send, data, false).await?;
                    }
                    send.send_data(Bytes::new(), true)?;
                    return Ok(());
                }

                drain(body).await?;
                burn(config.work);
                send_body(&mut send, &chunk, config.resp_body).await
            }

            async fn serve(
                socket: TcpStream,
                config: Config,
                chunk: Bytes,
            ) -> Result<(), BoxError> {
                socket.set_nodelay(true)?;
                let mut builder = server::Builder::new();
                builder
                    .initial_window_size(config.window)
                    .initial_connection_window_size(config.conn_window)
                    .max_concurrent_streams(config.streams as u32 * 2);
                let mut connection = builder.handshake(socket).await?;

                while let Some(result) = connection.accept().await {
                    let (request, respond) = result?;
                    let chunk = chunk.clone();
                    tokio::spawn(async move {
                        if let Err(err) = handle(request, respond, config, chunk).await {
                            eprintln!("server request error: {err}");
                        }
                    });
                }

                Ok(())
            }

            pub(super) async fn server(listener: TcpListener, config: Config) {
                let chunk = Bytes::from(vec![b'x'; config.chunk]);
                loop {
                    let Ok((socket, _)) = listener.accept().await else {
                        continue;
                    };
                    let chunk = chunk.clone();
                    tokio::spawn(async move {
                        // The benchmark drops its connections when it finishes.
                        let _ = serve(socket, config, chunk).await;
                    });
                }
            }

            async fn rpc(
                send_request: &mut client::SendRequest<Bytes>,
                config: Config,
                chunk: &Bytes,
            ) -> Result<(), BoxError> {
                let request = Request::builder()
                    .uri("http://localhost/")
                    .body(())
                    .unwrap();
                let end_of_stream = config.req_body == 0;
                let (response, mut send) = send_request.send_request(request, end_of_stream)?;

                if !end_of_stream {
                    send_body(&mut send, chunk, config.req_body).await?;
                }

                let mut body = response.await?.into_body();
                let received = drain(&mut body).await?;
                assert_eq!(received, config.resp_body);
                Ok(())
            }

            async fn echo(
                send_request: &mut client::SendRequest<Bytes>,
                config: Config,
                chunk: &Bytes,
                deadline: Instant,
                stats: &mut Stats,
            ) -> Result<(), BoxError> {
                let request = Request::builder()
                    .uri("http://localhost/")
                    .body(())
                    .unwrap();
                let (response, mut send) = send_request.send_request(request, false)?;
                let mut body = response.await?.into_body();
                let message = chunk.slice(..config.req_body.clamp(1, chunk.len()));

                for _ in 0..config.echo_msgs {
                    if Instant::now() >= deadline {
                        break;
                    }

                    let started = Instant::now();
                    send_chunk(&mut send, message.clone(), false).await?;

                    let mut received = 0;
                    while received < message.len() {
                        let Some(data) = body.data().await else {
                            return Err("echo stream ended early".into());
                        };
                        let data = data?;
                        received += data.len();
                        body.flow_control().release_capacity(data.len())?;
                    }

                    stats.ops += 1;
                    stats.latencies.push(started.elapsed().as_micros() as u32);
                }

                send.send_data(Bytes::new(), true)?;
                drain(&mut body).await?;
                Ok(())
            }

            async fn worker(
                mut send_request: client::SendRequest<Bytes>,
                config: Config,
                chunk: Bytes,
                deadline: Instant,
                remaining: Arc<AtomicUsize>,
            ) -> Result<Stats, BoxError> {
                let mut stats = Stats::default();

                while Instant::now() < deadline {
                    // With a request count, stop once it is used up.
                    if config.requests != 0
                        && remaining
                            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                                n.checked_sub(1)
                            })
                            .is_err()
                    {
                        break;
                    }

                    send_request = send_request.ready().await?;

                    match config.scenario {
                        Scenario::Rpc => {
                            let started = Instant::now();
                            rpc(&mut send_request, config, &chunk).await?;
                            stats.ops += 1;
                            stats.latencies.push(started.elapsed().as_micros() as u32);
                        }
                        Scenario::Echo => {
                            echo(&mut send_request, config, &chunk, deadline, &mut stats).await?;
                        }
                    }
                }

                Ok(stats)
            }

            pub(super) async fn client(
                addr: std::net::SocketAddr,
                config: Config,
            ) -> Result<Stats, BoxError> {
                let chunk = Bytes::from(vec![b'y'; config.chunk]);
                let mut senders = Vec::with_capacity(config.conns);

                for _ in 0..config.conns {
                    let socket = TcpStream::connect(addr).await?;
                    socket.set_nodelay(true)?;
                    let mut builder = client::Builder::new();
                    builder
                        .initial_window_size(config.window)
                        .initial_connection_window_size(config.conn_window);
                    let (send_request, connection) = builder.handshake::<_, Bytes>(socket).await?;
                    tokio::spawn(async move {
                        if let Err(err) = connection.await {
                            eprintln!("client connection error: {err}");
                        }
                    });
                    senders.push(send_request.ready().await?);
                }

                let deadline = Instant::now() + config.duration;
                let remaining = Arc::new(AtomicUsize::new(config.requests));
                let mut workers = Vec::with_capacity(config.conns * config.streams);
                for send_request in &senders {
                    for _ in 0..config.streams {
                        workers.push(tokio::spawn(worker(
                            send_request.clone(),
                            config,
                            chunk.clone(),
                            deadline,
                            remaining.clone(),
                        )));
                    }
                }

                let mut total = Stats::default();
                for worker in workers {
                    let stats = worker.await??;
                    total.ops += stats.ops;
                    total.latencies.extend(stats.latencies);
                }

                Ok(total)
            }
        }
    };
}

bench_impl!(fork, http2);
bench_impl!(upstream, h2);

fn percentile(sorted: &[u32], pct: f64) -> u32 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() - 1) as f64 * pct).round() as usize;
    sorted[idx]
}

fn main() {
    let config = Config::from_env();
    let lib = std::env::var("LIB").unwrap_or_else(|_| "http2".to_string());
    let upstream = lib == "h2";

    let server_rt = runtime(config.server_threads);
    let listener = server_rt
        .block_on(TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let addr = listener.local_addr().unwrap();

    if upstream {
        server_rt.spawn(upstream::server(listener, config));
    } else {
        server_rt.spawn(fork::server(listener, config));
    }
    // A current-thread runtime only runs its tasks while it is blocked on.
    let _server = if config.server_threads == 0 {
        Err(std::thread::spawn(move || {
            server_rt.block_on(std::future::pending::<()>())
        }))
    } else {
        Ok(server_rt)
    };

    let client_rt = runtime(config.client_threads);
    let cpu_before = cpu_ticks();
    let switches_before = voluntary_switches();
    let started = Instant::now();

    let stats = if upstream {
        client_rt.block_on(async { tokio::spawn(upstream::client(addr, config)).await.unwrap() })
    } else {
        client_rt.block_on(async { tokio::spawn(fork::client(addr, config)).await.unwrap() })
    };

    let elapsed = started.elapsed().as_secs_f64();
    let cpu_after = cpu_ticks();
    let switches = voluntary_switches().saturating_sub(switches_before);

    let mut stats = match stats {
        Ok(stats) => stats,
        Err(err) => {
            eprintln!("benchmark failed: {err}");
            std::process::exit(1);
        }
    };
    stats.latencies.sort_unstable();

    let ops = stats.ops as f64;
    let bytes = match config.scenario {
        Scenario::Rpc => ops * (config.req_body + config.resp_body) as f64,
        Scenario::Echo => ops * 2.0 * config.req_body.clamp(1, config.chunk) as f64,
    };
    let user = (cpu_after.0 - cpu_before.0) as f64 / 100.0;
    let system = (cpu_after.1 - cpu_before.1) as f64 / 100.0;

    println!(
        "lib={lib} scenario={:?} srv={} cli={} conns={} streams={} | {:>9.0} ops/s {:>8.1} MiB/s | \
         p50={}us p99={}us max={}us | cpu={:.2}s (usr {:.2} sys {:.2}) {:.1}us/op | csw/op={:.2}",
        config.scenario,
        config.server_threads,
        config.client_threads,
        config.conns,
        config.streams,
        ops / elapsed,
        bytes / elapsed / (1024.0 * 1024.0),
        percentile(&stats.latencies, 0.50),
        percentile(&stats.latencies, 0.99),
        stats.latencies.last().copied().unwrap_or(0),
        user + system,
        user,
        system,
        (user + system) * 1e6 / ops.max(1.0),
        switches as f64 / ops.max(1.0),
    );

    // Skip runtime shutdown: the server tasks never finish.
    std::process::exit(0);
}
