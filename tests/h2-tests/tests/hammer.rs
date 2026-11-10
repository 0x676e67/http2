use futures::{FutureExt, StreamExt, TryFutureExt};
use h2_support::prelude::*;

use std::io;
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};
use tokio::net::{TcpListener, TcpStream};

struct Server {
    addr: SocketAddr,
    reqs: Arc<AtomicUsize>,
    _join: Option<thread::JoinHandle<()>>,
}

impl Server {
    fn serve<F>(mk_data: F) -> Self
    where
        F: Fn() -> Bytes,
        F: Send + Sync + 'static,
    {
        let mk_data = Arc::new(mk_data);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let listener = rt
            .block_on(TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))))
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let reqs = Arc::new(AtomicUsize::new(0));
        let reqs2 = reqs.clone();
        let join = thread::spawn(move || {
            let server = async move {
                loop {
                    let socket = listener.accept().await.map(|(s, _)| s);
                    let reqs = reqs2.clone();
                    let mk_data = mk_data.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_request(socket, reqs, mk_data).await {
                            eprintln!("serve conn error: {:?}", e)
                        }
                    });
                }
            };

            rt.block_on(server);
        });

        Self {
            addr,
            _join: Some(join),
            reqs,
        }
    }

    fn addr(&self) -> SocketAddr {
        self.addr
    }

    fn request_count(&self) -> usize {
        self.reqs.load(Ordering::Acquire)
    }
}

async fn handle_request<F>(
    socket: io::Result<TcpStream>,
    reqs: Arc<AtomicUsize>,
    mk_data: Arc<F>,
) -> Result<(), Box<dyn std::error::Error>>
where
    F: Fn() -> Bytes,
    F: Send + Sync + 'static,
{
    let mut conn = server::handshake(socket?).await?;
    while let Some(result) = conn.next().await {
        let (_, mut respond) = result?;
        reqs.fetch_add(1, Ordering::Release);
        let response = Response::builder().status(StatusCode::OK).body(()).unwrap();
        let mut send = respond.send_response(response, false)?;
        send.send_data(mk_data(), true)?;
    }
    Ok(())
}

#[test]
fn hammer_client_concurrency() {
    // This reproduces issue #326.
    const N: usize = 5000;

    let server = Server::serve(|| Bytes::from_static(b"hello world!"));

    let addr = server.addr();
    let rsps = Arc::new(AtomicUsize::new(0));

    for i in 0..N {
        print!("sending {}", i);
        let rsps = rsps.clone();
        let tcp = TcpStream::connect(&addr);
        let tcp = tcp
            .then(|res| {
                let tcp = res.unwrap();
                client::handshake(tcp)
            })
            .then(move |res| {
                let rsps = rsps;
                let (mut client, h2) = res.unwrap();
                let request = Request::builder()
                    .uri("https://http2.akamai.com/")
                    .body(())
                    .unwrap();

                let (response, mut stream) = client.send_request(request, false).unwrap();
                stream.send_trailers(HeaderMap::new()).unwrap();

                tokio::spawn(async move {
                    h2.await.unwrap();
                });

                response
                    .and_then(|response| {
                        let mut body = response.into_body();

                        async move {
                            while let Some(res) = body.data().await {
                                res?;
                            }
                            body.trailers().await?;
                            Ok(())
                        }
                    })
                    .map_err(|e| {
                        panic!("client error: {:?}", e);
                    })
                    .map(move |_| {
                        rsps.fetch_add(1, Ordering::Release);
                    })
            });

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(tcp);
        println!("...done");
    }

    println!("all done");

    assert_eq!(N, rsps.load(Ordering::Acquire));
    assert_eq!(N, server.request_count());
}

/// Streams of one connection, driven from several worker threads, that send
/// and receive bodies past their windows and are dropped at every stage.
///
/// Their handles and the connection reach the same streams at once, so a
/// wake-up or a change lost between them shows as a stream that never ends.
#[test]
fn concurrent_streams_on_worker_threads_all_finish() {
    const TASKS: usize = 64;
    const REQUESTS: usize = 48;
    const SIZES: [usize; 4] = [0, 1, 1_000, 100_000];
    const CHUNK: usize = 16_384;

    async fn send_body(send: &mut SendStream<Bytes>, mut len: usize) -> Result<(), h2::Error> {
        while len > 0 {
            send.reserve_capacity(len.min(CHUNK));
            let capacity = match poll_fn(|cx| send.poll_capacity(cx)).await {
                Some(capacity) => capacity?,
                None => return Err(Reason::CANCEL.into()),
            };
            let chunk = capacity.min(len);
            send.send_data(vec![0; chunk].into(), false)?;
            len -= chunk;
        }
        send.send_data(Bytes::new(), true)
    }

    async fn echo_size(
        request: Request<RecvStream>,
        mut respond: server::SendResponse<Bytes>,
    ) -> Result<(), h2::Error> {
        let mut body = request.into_body();
        let mut len = 0;
        while let Some(chunk) = body.data().await {
            let chunk = chunk?;
            len += chunk.len();
            body.flow_control().release_capacity(chunk.len())?;
        }

        let mut send = respond.send_response(Response::new(()), false)?;
        send_body(&mut send, len).await
    }

    async fn request(
        mut client: client::SendRequest<Bytes>,
        size: usize,
        stage: usize,
    ) -> client::SendRequest<Bytes> {
        client = client.ready().await.unwrap();
        let request = Request::post("https://example.com/").body(()).unwrap();
        let (response, mut send) = client.send_request(request, false).unwrap();

        // Dropped before the request has all been sent.
        if stage == 0 {
            return client;
        }
        send_body(&mut send, size).await.unwrap();

        // Dropped while the response is on its way.
        if stage == 1 {
            return client;
        }
        let mut body = response.await.unwrap().into_body();

        let mut received = 0;
        while let Some(chunk) = body.data().await {
            let len = chunk.unwrap().len();
            received += len;
            // Dropped part way through the body, its capacity unreleased.
            if stage == 2 {
                return client;
            }
            body.flow_control().release_capacity(len).unwrap();
        }
        assert_eq!(received, size);
        assert!(body.is_end_stream());
        client
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();

    for coalesce in [false, true] {
        rt.block_on(async {
            let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
            let addr = listener.local_addr().unwrap();

            let server = tokio::spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                socket.set_nodelay(true).unwrap();
                // The limits on resets are not what this is after.
                let mut conn = server::Builder::new()
                    .coalesce_writes(coalesce)
                    .max_pending_accept_reset_streams(usize::MAX)
                    .max_local_error_reset_streams(None)
                    .handshake::<_, Bytes>(socket)
                    .await
                    .unwrap();
                // Ends with the client's connection, which can leave streams
                // that it dropped open here. An earlier error fails the client.
                while let Some(Ok((request, respond))) = conn.next().await {
                    // A stream the client dropped fails here, as it should.
                    tokio::spawn(echo_size(request, respond));
                }
            });

            let tcp = TcpStream::connect(addr).await.unwrap();
            tcp.set_nodelay(true).unwrap();
            let (client, conn) = client::Builder::new()
                .coalesce_writes(coalesce)
                .max_local_error_reset_streams(None)
                .handshake::<_, Bytes>(tcp)
                .await
                .unwrap();
            let conn = tokio::spawn(conn);

            let tasks: Vec<_> = (0..TASKS)
                .map(|task| {
                    let mut client = client.clone();
                    tokio::spawn(async move {
                        for n in 0..REQUESTS {
                            let size = SIZES[(task + n) % SIZES.len()];
                            client = request(client, size, (task / SIZES.len() + n) % 4).await;
                        }
                    })
                })
                .collect();
            drop(client);

            let finished = async {
                for task in tasks {
                    task.await.unwrap();
                }
                // With its streams and handles gone, the connection closes.
                conn.await.unwrap().unwrap();
                server.await.unwrap();
            };
            tokio::time::timeout(Duration::from_secs(60), finished)
                .await
                .expect("streams or their connection did not finish");
        });
    }
}
