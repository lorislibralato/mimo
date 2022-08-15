use crate::peet::PeetResponse;
use hyper::{body::to_bytes, client::HttpConnector, Body, Client, Method, Request, StatusCode};
use hyper_rustls::{ConfigBuilderExt, HttpsConnector, HttpsConnectorBuilder};
use rustls::{cipher_suite, ClientConfig};
mod peet;

pub async fn create_connector() -> Client<HttpsConnector<HttpConnector>> {
    let tls_config = ClientConfig::builder()
        .with_cipher_suites(&[
            cipher_suite::TLS13_AES_128_GCM_SHA256,
            cipher_suite::TLS13_AES_256_GCM_SHA384,
            cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
            cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            // start weak
            cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            cipher_suite::TLS_RSA_WITH_AES_128_GCM_SHA256,
            cipher_suite::TLS_RSA_WITH_AES_256_GCM_SHA384,
            cipher_suite::TLS_RSA_WITH_AES_128_CBC_SHA,
            cipher_suite::TLS_RSA_WITH_AES_256_CBC_SHA, // end weak
        ])
        .with_safe_default_kx_groups()
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_native_roots()
        .with_no_client_auth();

    let connector = HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();
    Client::builder()
        .http2_initial_connection_window_size(15663105 + (1 << 16) - 1)
        .http2_initial_stream_window_size(6291456)
        .build(connector)
}

static CHROME_HEADERS: [(&str, &str); 13] = [
    ("cache-control", "max-age=0"),
    ("sec-ch-ua", "\"Chromium\";v=\"104\", \" Not A;Brand\";v=\"99\", \"Google Chrome\";v=\"104\""),
    ("sec-ch-ua-mobile", "?0"),
    ("sec-ch-ua-platform", "\"Linux\""),
    ("upgrade-insecure-requests" ,"1"),
    ("user-agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36"),
    ("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"),
    ("sec-fetch-site", "none"),
    ("sec-fetch-mode", "navigate"),
    ("sec-fetch-user", "?1"),
    ("sec-fetch-dest", "document"),
    ("accept-encoding", "gzip, deflate, br"),
    ("accept-language", "en-GB,en-US;q=0.9,en;q=0.8")
];

pub async fn get_peet_response() -> PeetResponse {
    let req = Request::builder()
        .uri("https://tls.peet.ws/api/all")
        .method(Method::GET);

    let req = CHROME_HEADERS
        .iter()
        .fold(req, |req, h| req.header(h.0, h.1));

    let req = req.body(Body::empty()).unwrap();

    let client = create_connector().await;
    let (parts, body) = client.request(req).await.unwrap().into_parts();
    assert_eq!(parts.status, StatusCode::OK);

    let body = to_bytes(body).await.unwrap();
    println!("{}", std::str::from_utf8(&body).unwrap());

    serde_json::from_slice(&body).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peet::PeetResponse;
    use once_cell::sync::Lazy;
    use tokio::sync::OnceCell as AsyncCell;

    static PEET_RESPONSE: AsyncCell<PeetResponse> = AsyncCell::const_new();
    static GREASE: &str = "TLS_GREASE (0x";

    static BR_JSON: &str = include_str!("../data/chrome.json");
    static BR: Lazy<PeetResponse> = Lazy::new(|| serde_json::from_str(BR_JSON).unwrap());

    fn check_list_order_ignore_grease(left: &Vec<String>, right: &Vec<String>) {
        assert_eq!(
            left.iter()
                .filter(|s| !s.starts_with(GREASE))
                .collect::<Vec<_>>(),
            right
                .iter()
                .filter(|s| !s.starts_with(GREASE))
                .collect::<Vec<_>>()
        )
    }

    #[tokio::test]
    async fn test_request_validity() {
        let r = PEET_RESPONSE.get_or_init(get_peet_response).await;
        assert_eq!(r.http_version, BR.http_version);
        assert_eq!(r.method, BR.method);
        assert_eq!(r.path, BR.path);
    }

    #[tokio::test]
    async fn test_grease() {
        let r = PEET_RESPONSE.get_or_init(get_peet_response).await;

        fn check_same_grease_amount(left: &Vec<String>, right: &Vec<String>) {
            assert_eq!(
                left.iter().filter(|s| s.starts_with(GREASE)).count(),
                right.iter().filter(|s| s.starts_with(GREASE)).count()
            )
        }

        check_same_grease_amount(&r.tls.ciphers, &BR.tls.ciphers);
        check_same_grease_amount(&r.tls.curves, &BR.tls.curves);
        check_same_grease_amount(&r.tls.extensions, &BR.tls.extensions);
    }

    #[tokio::test]
    async fn test_ciphers() {
        let r = PEET_RESPONSE.get_or_init(get_peet_response).await;
        check_list_order_ignore_grease(&r.tls.ciphers, &BR.tls.ciphers);
    }

    #[tokio::test]
    async fn test_curves() {
        let r = PEET_RESPONSE.get_or_init(get_peet_response).await;
        check_list_order_ignore_grease(&r.tls.curves, &BR.tls.curves);
    }

    #[tokio::test]
    async fn test_extensions() {
        let r = PEET_RESPONSE.get_or_init(get_peet_response).await;
        check_list_order_ignore_grease(&r.tls.extensions, &BR.tls.extensions);
    }

    #[tokio::test]
    async fn test_versions() {
        let r = PEET_RESPONSE.get_or_init(get_peet_response).await;
        assert_eq!(r.tls.version, BR.tls.version);
        assert_eq!(r.tls.versions, BR.tls.versions);
    }

    #[tokio::test]
    async fn test_points() {
        let r = PEET_RESPONSE.get_or_init(get_peet_response).await;
        assert_eq!(r.tls.points, BR.tls.points);
    }

    #[tokio::test]
    async fn test_protocols() {
        let r = PEET_RESPONSE.get_or_init(get_peet_response).await;
        assert_eq!(r.tls.protocols, BR.tls.protocols)
    }

    #[tokio::test]
    async fn test_ja3() {
        let r = PEET_RESPONSE.get_or_init(get_peet_response).await;
        assert_eq!(r.tls.ja3, BR.tls.ja3);
        assert_eq!(r.tls.ja3_hash, BR.tls.ja3_hash);
    }

    #[tokio::test]
    async fn test_akamai_fp() {
        let r = PEET_RESPONSE.get_or_init(get_peet_response).await;
        assert_eq!(r.http2.akamai_fingerprint, BR.http2.akamai_fingerprint);
        assert_eq!(
            r.http2.akamai_fingerprint_hash,
            BR.http2.akamai_fingerprint_hash
        );
    }

    #[tokio::test]
    async fn test_http2_settings() {
        let r = PEET_RESPONSE.get_or_init(get_peet_response).await;
        assert_eq!(r.http2.sent_frames[0], BR.http2.sent_frames[0]);
    }

    #[tokio::test]
    async fn test_http2_windows_update() {
        let r = PEET_RESPONSE.get_or_init(get_peet_response).await;
        assert_eq!(r.http2.sent_frames[1], BR.http2.sent_frames[1]);
    }

    #[tokio::test]
    async fn test_http2_headers_frame() {
        let r = PEET_RESPONSE.get_or_init(get_peet_response).await;
        let sent_frame = &r.http2.sent_frames[2];
        let br_frame = &r.http2.sent_frames[2];

        assert_eq!(sent_frame.frame_type, br_frame.frame_type);
        assert_eq!(sent_frame.length, br_frame.length);
        assert_eq!(sent_frame.stream_id, br_frame.stream_id);
    }

    #[tokio::test]
    async fn test_http2_pseudo_headers_order() {
        let r = PEET_RESPONSE.get_or_init(get_peet_response).await;
        assert_eq!(
            r.http2.sent_frames[2]
                .headers
                .iter()
                .filter(|s| s.starts_with(':'))
                .collect::<Vec<_>>(),
            BR.http2.sent_frames[2]
                .headers
                .iter()
                .filter(|s| s.starts_with(':'))
                .collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn test_http2_headers_order() {
        let r = PEET_RESPONSE.get_or_init(get_peet_response).await;
        assert_eq!(
            r.http2.sent_frames[2]
                .headers
                .iter()
                .filter(|s| !s.starts_with(':'))
                .collect::<Vec<_>>(),
            BR.http2.sent_frames[2]
                .headers
                .iter()
                .filter(|s| !s.starts_with(':'))
                .collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn test_http2_headers_flags() {
        let r = PEET_RESPONSE.get_or_init(get_peet_response).await;
        let br_flags = BR.http2.sent_frames[2].flags.as_ref().unwrap();

        assert_eq!(
            r.http2.sent_frames[2]
                .flags
                .as_ref()
                .unwrap()
                .iter()
                .fold(0, |l, f| {
                    if br_flags.contains(f) {
                        l + 1
                    } else {
                        panic!("flag: {} should not be present", f)
                    }
                }),
            br_flags.len()
        )
    }

    #[tokio::test]
    async fn test_http2_headers_priority() {
        let r = PEET_RESPONSE.get_or_init(get_peet_response).await;
        assert_eq!(
            r.http2.sent_frames[2].priority,
            BR.http2.sent_frames[2].priority
        )
    }
}
