extern crate bytes;
extern crate quickcheck;
extern crate rand;

use hpack::{Header, Decoder, Encoder, Encode};

use http::header::{HeaderName, HeaderValue};

use self::bytes::{BytesMut, Bytes};
use self::quickcheck::{QuickCheck, Arbitrary, Gen, TestResult};
use self::rand::{StdRng, Rng, SeedableRng};

use std::io::Cursor;

const MAX_CHUNK: usize = 2 * 1024;

#[test]
fn hpack_fuzz() {
    fn prop(fuzz: FuzzHpack) -> TestResult {
        fuzz.run();
        TestResult::from_bool(true)
    }

    QuickCheck::new()
        .tests(100)
        .quickcheck(prop as fn(FuzzHpack) -> TestResult)
}

#[derive(Debug, Clone)]
struct FuzzHpack {
    // The magic seed that makes the test case reproducible
    seed: [usize; 4],

    // The set of headers to encode / decode
    frames: Vec<HeaderFrame>,

    // The list of chunk sizes to do it in
    chunks: Vec<usize>,

    // Number of times reduced
    reduced: usize,
}

#[derive(Debug, Clone)]
struct HeaderFrame {
    resizes: Vec<usize>,
    headers: Vec<Header<Option<HeaderName>>>,
}

impl FuzzHpack {
    fn new(seed: [usize; 4]) -> FuzzHpack {
        // Seed the RNG
        let mut rng = StdRng::from_seed(&seed);

        // Generates a bunch of source headers
        let mut source: Vec<Header<Option<HeaderName>>> = vec![];

        for _ in 0..2000 {
            source.push(gen_header(&mut rng));
        }

        // Actual test run headers
        let num: usize = rng.gen_range(40, 500);

        let mut frames: Vec<HeaderFrame> = vec![];
        let mut added = 0;

        let skew: i32 = rng.gen_range(1, 5);

        // Rough number of headers to add
        while added < num {
            let mut frame = HeaderFrame {
                resizes: vec![],
                headers: vec![],
            };

            match rng.gen_range(0, 20) {
                0 => {
                    // Two resizes
                    let high = rng.gen_range(128, MAX_CHUNK * 2);
                    let low = rng.gen_range(0, high);

                    frame.resizes.extend(&[low, high]);
                }
                1...3 => {
                    frame.resizes.push(rng.gen_range(128, MAX_CHUNK * 2));
                }
                _ => {}
            }

            for _ in 0..rng.gen_range(1, (num - added) + 1) {
                added += 1;

                let x: f64 = rng.gen_range(0.0, 1.0);
                let x = x.powi(skew);

                let i = (x * source.len() as f64) as usize;
                frame.headers.push(source[i].clone());
            }

            frames.push(frame);
        }

        // Now, generate the buffer sizes used to encode
        let mut chunks = vec![];

        for _ in 0..rng.gen_range(0, 100) {
            chunks.push(rng.gen_range(0, MAX_CHUNK));
        }

        FuzzHpack {
            seed: seed,
            frames: frames,
            chunks: chunks,
            reduced: 0,
        }
    }

    fn run(self) {
        let mut chunks = self.chunks;
        let frames = self.frames;
        let mut expect = vec![];

        let mut encoder = Encoder::default();
        let mut decoder = Decoder::default();

        for frame in frames {
            expect.extend(frame.headers.clone());

            let mut index = None;
            let mut input = frame.headers.into_iter();

            let mut buf = BytesMut::with_capacity(
                chunks.pop().unwrap_or(MAX_CHUNK));

            if let Some(max) = frame.resizes.iter().max() {
                decoder.queue_size_update(*max);
            }

            // Apply resizes
            for resize in &frame.resizes {
                encoder.update_max_size(*resize);
            }

            loop {
                match encoder.encode(index.take(), &mut input, &mut buf) {
                    Encode::Full => break,
                    Encode::Partial(i) => {
                        index = Some(i);

                        // Decode the chunk!
                        decoder.decode(&mut Cursor::new(buf.into()), |e| {
                            assert_eq!(e, expect.remove(0).reify().unwrap());
                        }).unwrap();

                        buf = BytesMut::with_capacity(
                            chunks.pop().unwrap_or(MAX_CHUNK));
                    }
                }
            }

            // Decode the chunk!
            decoder.decode(&mut Cursor::new(buf.into()), |e| {
                assert_eq!(e, expect.remove(0).reify().unwrap());
            }).unwrap();
        }

        assert_eq!(0, expect.len());
    }
}

impl Arbitrary for FuzzHpack {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        FuzzHpack::new(quickcheck::Rng::gen(g))
    }
}

fn gen_header(g: &mut StdRng) -> Header<Option<HeaderName>> {
    use http::StatusCode;
    use http::method::{self, Method};

    if g.gen_weighted_bool(10) {
        match g.next_u32() % 5 {
            0 => {
                let value = gen_string(g, 4, 20);
                Header::Authority(to_shared(value))
            }
            1 => {
                let method = match g.next_u32() % 6 {
                    0 => method::GET,
                    1 => method::POST,
                    2 => method::PUT,
                    3 => method::PATCH,
                    4 => method::DELETE,
                    5 => {
                        let n: usize = g.gen_range(3, 7);
                        let bytes: Vec<u8> = (0..n).map(|_| {
                            g.choose(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ").unwrap().clone()
                        }).collect();

                        Method::from_bytes(&bytes).unwrap()
                    }
                    _ => unreachable!(),
                };

                Header::Method(method)
            }
            2 => {
                let value = match g.next_u32() % 2 {
                    0 => "http",
                    1 => "https",
                    _ => unreachable!(),
                };

                Header::Scheme(to_shared(value.to_string()))
            }
            3 => {
                let value = match g.next_u32() % 100 {
                    0 => "/".to_string(),
                    1 => "/index.html".to_string(),
                    _ => gen_string(g, 2, 20),
                };

                Header::Path(to_shared(value))
            }
            4 => {
                let status = (g.gen::<u16>() % 500) + 100;

                Header::Status(StatusCode::from_u16(status).unwrap())
            }
            _ => unreachable!(),
        }
    } else {
        let name = gen_header_name(g);
        let mut value = gen_header_value(g);

        if g.gen_weighted_bool(30) {
            value.set_sensitive(true);
        }

        Header::Field { name: Some(name), value: value }
    }
}

fn gen_header_name(g: &mut StdRng) -> HeaderName {
    use http::header;

    if g.gen_weighted_bool(2) {
        g.choose(&[
            header::ACCEPT,
            header::ACCEPT_CHARSET,
            header::ACCEPT_ENCODING,
            header::ACCEPT_LANGUAGE,
            header::ACCEPT_RANGES,
            header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            header::ACCESS_CONTROL_ALLOW_METHODS,
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            header::ACCESS_CONTROL_EXPOSE_HEADERS,
            header::ACCESS_CONTROL_MAX_AGE,
            header::ACCESS_CONTROL_REQUEST_HEADERS,
            header::ACCESS_CONTROL_REQUEST_METHOD,
            header::AGE,
            header::ALLOW,
            header::ALT_SVC,
            header::AUTHORIZATION,
            header::CACHE_CONTROL,
            header::CONNECTION,
            header::CONTENT_DISPOSITION,
            header::CONTENT_ENCODING,
            header::CONTENT_LANGUAGE,
            header::CONTENT_LENGTH,
            header::CONTENT_LOCATION,
            header::CONTENT_RANGE,
            header::CONTENT_SECURITY_POLICY,
            header::CONTENT_SECURITY_POLICY_REPORT_ONLY,
            header::CONTENT_TYPE,
            header::COOKIE,
            header::DNT,
            header::DATE,
            header::ETAG,
            header::EXPECT,
            header::EXPIRES,
            header::FORWARDED,
            header::FROM,
            header::HOST,
            header::IF_MATCH,
            header::IF_MODIFIED_SINCE,
            header::IF_NONE_MATCH,
            header::IF_RANGE,
            header::IF_UNMODIFIED_SINCE,
            header::LAST_MODIFIED,
            header::LINK,
            header::LOCATION,
            header::MAX_FORWARDS,
            header::ORIGIN,
            header::PRAGMA,
            header::PROXY_AUTHENTICATE,
            header::PROXY_AUTHORIZATION,
            header::PUBLIC_KEY_PINS,
            header::PUBLIC_KEY_PINS_REPORT_ONLY,
            header::RANGE,
            header::REFERER,
            header::REFERRER_POLICY,
            header::REFRESH,
            header::RETRY_AFTER,
            header::SERVER,
            header::SET_COOKIE,
            header::STRICT_TRANSPORT_SECURITY,
            header::TE,
            header::TRAILER,
            header::TRANSFER_ENCODING,
            header::USER_AGENT,
            header::UPGRADE,
            header::UPGRADE_INSECURE_REQUESTS,
            header::VARY,
            header::VIA,
            header::WARNING,
            header::WWW_AUTHENTICATE,
            header::X_CONTENT_TYPE_OPTIONS,
            header::X_DNS_PREFETCH_CONTROL,
            header::X_FRAME_OPTIONS,
            header::X_XSS_PROTECTION,
        ]).unwrap().clone()
    } else {
        let value = gen_string(g, 1, 25);
        HeaderName::from_bytes(value.as_bytes()).unwrap()
    }
}

fn gen_header_value(g: &mut StdRng) -> HeaderValue {
    let value = gen_string(g, 0, 70);
    HeaderValue::try_from_bytes(value.as_bytes()).unwrap()
}

fn gen_string(g: &mut StdRng, min: usize, max: usize) -> String {
    let bytes: Vec<_> = (min..max).map(|_| {
        // Chars to pick from
        g.choose(b"ABCDEFGHIJKLMNOPQRSTUVabcdefghilpqrstuvwxyz----").unwrap().clone()
    }).collect();

    String::from_utf8(bytes).unwrap()
}

fn to_shared(src: String) -> ::string::String<Bytes> {
    let b: Bytes = src.into();
    unsafe { ::string::String::from_utf8_unchecked(b) }
}
