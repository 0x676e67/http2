use bytes::Bytes;
use h2::{
    client,
    server::{self, SendResponse},
    RecvStream,
};
use http::Request;
use http2 as h2;

use std::{error::Error, time::Duration};

use tokio::net::{TcpListener, TcpStream};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

const NUM_REQUESTS_TO_SEND: usize = 100;

// The actual server.
async fn server(addr: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
    let listener = TcpListener::bind(addr).await?;

    loop {
        if let Ok((socket, _peer_addr)) = listener.accept().await {
            tokio::spawn(async move {
                if let Err(e) = serve(socket).await {
                    println!("  -> err={:?}", e);
                }
            });
        }
    }
}

async fn serve(socket: TcpStream) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut connection = server::handshake(socket).await?;
    while let Some(result) = connection.accept().await {
        let (request, respond) = result?;
        tokio::spawn(async move {
            if let Err(e) = handle_request(request, respond).await {
                println!("error while handling request: {}", e);
            }
        });
    }
    Ok(())
}

async fn handle_request(
    mut request: Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let body = request.body_mut();
    while let Some(data) = body.data().await {
        let data = data?;
        let _ = body.flow_control().release_capacity(data.len());
    }
    let response = http::Response::new(());
    let mut send = respond.send_response(response, false)?;
    send.send_data(Bytes::from_static(b"pong"), true)?;

    Ok(())
}

// The benchmark
async fn send_requests(addr: &str) -> Result<(), Box<dyn Error>> {
    let tcp = loop {
        let Ok(tcp) = TcpStream::connect(addr).await else {
            continue;
        };
        break tcp;
    };
    let (client, h2) = client::handshake(tcp).await?;
    // Spawn a task to run the conn...
    tokio::spawn(async move {
        if let Err(e) = h2.await {
            println!("GOT ERR={:?}", e);
        }
    });

    let mut handles = Vec::with_capacity(NUM_REQUESTS_TO_SEND);
    for _i in 0..NUM_REQUESTS_TO_SEND {
        let mut client = client.clone();
        let task = tokio::spawn(async move {
            let request = Request::builder().body(()).unwrap();

            let (response, _) = client.send_request(request, true).unwrap();
            let response = response.await.unwrap();
            let mut body = response.into_body();
            while let Some(_chunk) = body.data().await {}
        });
        handles.push(task);
    }

    for handle in handles {
        handle.await.unwrap();
    }

    Ok(())
}

fn bench_single_thread(c: &mut Criterion) {
    let addr = "127.0.0.1:5928";
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(server(addr)).unwrap();
    });
    std::thread::sleep(Duration::from_millis(500));

    c.bench_with_input(
        BenchmarkId::new("single_thread", addr),
        &addr,
        |b, &addr| {
            b.to_async(
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap(),
            )
            .iter(|| send_requests(addr));
        },
    );
}

fn bench_multi_thread(c: &mut Criterion) {
    let addr = "127.0.0.1:5929";
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(server(addr)).unwrap();
    });

    std::thread::sleep(Duration::from_millis(500));

    c.bench_with_input(
        BenchmarkId::new("multi_thread", addr),
        &addr,
        |b, &addr| {
            b.to_async(
                tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .unwrap(),
            )
            .iter(|| send_requests(addr));
        },
    );
}

criterion_group!(benches, bench_single_thread, bench_multi_thread);
criterion_main!(benches);
