//! HTTPS for the credential issuer and its authorization server.
//!
//! A name the system trust store accepts is verified with that store. A
//! loopback name (`localhost`, `127.0.0.1`, `::1`) is also accepted when the
//! store does not know the issuer's CA. iya-sts on this machine publishes a
//! process CA that the browser already trusts and the system store does not.
//! Any other host still has to chain to a trusted CA.

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Once, OnceLock};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, Error, RootCertStore, SignatureScheme,
};

const MAX_BODY: usize = 2 * 1024 * 1024;
const MAX_HEADER: usize = 64 * 1024;

#[derive(Clone)]
pub(crate) struct RawResponse {
    pub status: u16,
    pub body: Vec<u8>,
    /// Certificates the TLS server presented, leaf first. Empty for plain HTTP.
    /// The last redirect hop is the one recorded.
    pub peer_certs: Vec<Vec<u8>>,
    /// The URL that produced this response, after redirects.
    pub final_url: String,
}

pub(crate) fn exchange(
    method: &str,
    url: &str,
    content_type: Option<&str>,
    authorization: Option<&str>,
    body: &[u8],
) -> Result<RawResponse, String> {
    let mut current = url.to_string();
    for _ in 0..5 {
        let parts = UrlParts::parse(&current)?;
        let request = build_request(&parts, method, content_type, authorization, body);
        let (bytes, peer_certs) = talk(&parts, &request)?;
        let response = parse_response(&bytes)?;
        if method == "GET" && matches!(response.status, 301 | 302 | 307 | 308) {
            let location = response
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("location"))
                .map(|(_, value)| value.clone())
                .ok_or_else(|| "a redirect had no Location".to_string())?;
            current = resolve(&parts, &location)?;
            continue;
        }
        return Ok(RawResponse {
            status: response.status,
            body: response.body,
            peer_certs,
            final_url: current,
        });
    }
    Err("too many redirects".to_string())
}

struct UrlParts {
    https: bool,
    host: String,
    port: u16,
    path: String,
}

impl UrlParts {
    fn parse(url: &str) -> Result<Self, String> {
        let (https, rest) = if let Some(rest) = url.strip_prefix("https://") {
            (true, rest)
        } else if let Some(rest) = url.strip_prefix("http://") {
            (false, rest)
        } else {
            return Err("the URL is not http or https".to_string());
        };
        if rest.is_empty() || rest.contains('@') {
            return Err("the URL has no host".to_string());
        }
        let (authority, path) = match rest.find('/') {
            Some(index) => (&rest[..index], rest[index..].to_string()),
            None => (rest, "/".to_string()),
        };
        let (host, port) = split_host_port(authority, if https { 443 } else { 80 })?;
        if host.is_empty() || path.is_empty() {
            return Err("the URL has no host".to_string());
        }
        Ok(Self {
            https,
            host,
            port,
            path,
        })
    }

    fn origin(&self) -> String {
        let scheme = if self.https { "https" } else { "http" };
        if (self.https && self.port == 443) || (!self.https && self.port == 80) {
            format!("{scheme}://{}", self.host)
        } else {
            format!("{scheme}://{}:{}", self.host, self.port)
        }
    }
}

fn split_host_port(authority: &str, default_port: u16) -> Result<(String, u16), String> {
    if let Some(host) = authority.strip_prefix('[') {
        let end = host
            .find(']')
            .ok_or_else(|| "the URL has an unfinished IPv6 host".to_string())?;
        let host_name = host[..end].to_string();
        let after = &host[end + 1..];
        if after.is_empty() {
            return Ok((host_name, default_port));
        }
        let port = after
            .strip_prefix(':')
            .ok_or_else(|| "the URL host is not usable".to_string())?
            .parse()
            .map_err(|_| "the URL port is not a number".to_string())?;
        return Ok((host_name, port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && port.chars().all(|ch| ch.is_ascii_digit()) => {
            let port = port
                .parse()
                .map_err(|_| "the URL port is not a number".to_string())?;
            Ok((host.to_string(), port))
        }
        _ => Ok((authority.to_string(), default_port)),
    }
}

fn resolve(base: &UrlParts, location: &str) -> Result<String, String> {
    if location.starts_with("https://") || location.starts_with("http://") {
        return Ok(location.to_string());
    }
    if let Some(path) = location.strip_prefix('/') {
        return Ok(format!("{}/{}", base.origin(), path));
    }
    Err("the redirect Location is not a URL this wallet follows".to_string())
}

fn build_request(
    parts: &UrlParts,
    method: &str,
    content_type: Option<&str>,
    authorization: Option<&str>,
    body: &[u8],
) -> Vec<u8> {
    let host = if parts.host.contains(':') {
        format!("[{}]", parts.host)
    } else {
        parts.host.clone()
    };
    let host = if (parts.https && parts.port == 443) || (!parts.https && parts.port == 80) {
        host
    } else {
        format!("{host}:{}", parts.port)
    };
    let mut text = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: oid4vc-wallet\r\nAccept: application/json\r\nConnection: close\r\n",
        path = parts.path
    );
    if let Some(content_type) = content_type {
        let _ = write!(text, "Content-Type: {content_type}\r\n");
    }
    if let Some(authorization) = authorization {
        let _ = write!(text, "Authorization: Bearer {authorization}\r\n");
    }
    if method != "GET" || !body.is_empty() {
        let _ = write!(text, "Content-Length: {}\r\n", body.len());
    }
    text.push_str("\r\n");
    let mut bytes = text.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

fn talk(parts: &UrlParts, request: &[u8]) -> Result<(Vec<u8>, Vec<Vec<u8>>), String> {
    let target = format!("{}:{}", bracket_host(&parts.host), parts.port);
    let mut last = "no address for the host".to_string();
    let addresses = target.to_socket_addrs().map_err(|err| err.to_string())?;
    for address in addresses {
        match TcpStream::connect_timeout(&address, Duration::from_secs(15)) {
            Ok(stream) => {
                stream
                    .set_read_timeout(Some(Duration::from_secs(20)))
                    .map_err(|err| err.to_string())?;
                stream
                    .set_write_timeout(Some(Duration::from_secs(20)))
                    .map_err(|err| err.to_string())?;
                return if parts.https {
                    talk_tls(&parts.host, stream, request)
                } else {
                    talk_plain(stream, request).map(|bytes| (bytes, Vec::new()))
                };
            }
            Err(err) => last = err.to_string(),
        }
    }
    Err(last)
}

fn bracket_host(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

fn talk_plain(mut stream: TcpStream, request: &[u8]) -> Result<Vec<u8>, String> {
    stream.write_all(request).map_err(|err| err.to_string())?;
    stream.flush().map_err(|err| err.to_string())?;
    let mut bytes = Vec::new();
    stream
        .take(MAX_BODY as u64 + MAX_HEADER as u64)
        .read_to_end(&mut bytes)
        .map_err(|err| err.to_string())?;
    Ok(bytes)
}

fn talk_tls(
    host: &str,
    mut stream: TcpStream,
    request: &[u8],
) -> Result<(Vec<u8>, Vec<Vec<u8>>), String> {
    install_provider();
    let name = ServerName::try_from(host.to_string())
        .map_err(|_| "the host is not a DNS name or an IP address".to_string())?;
    let mut connection =
        ClientConnection::new(tls_config(), name).map_err(|err| err.to_string())?;
    let bytes = {
        let mut tls = rustls::Stream::new(&mut connection, &mut stream);
        tls.write_all(request).map_err(|err| err.to_string())?;
        tls.flush().map_err(|err| err.to_string())?;
        let mut bytes = Vec::new();
        tls.take(MAX_BODY as u64 + MAX_HEADER as u64)
            .read_to_end(&mut bytes)
            .map_err(|err| err.to_string())?;
        bytes
    };
    let peer_certs = connection
        .peer_certificates()
        .map(|chain| chain.iter().map(|cert| cert.as_ref().to_vec()).collect())
        .unwrap_or_default();
    Ok((bytes, peer_certs))
}

fn install_provider() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn tls_config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut roots = RootCertStore::empty();
            roots.roots.extend(
                webpki_roots::TLS_SERVER_ROOTS
                    .iter()
                    .map(rustls::pki_types::TrustAnchor::to_owned),
            );
            let native = rustls_native_certs::load_native_certs();
            roots.add_parsable_certificates(native.certs);
            let webpki = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
                .build()
                .expect("the process trust store can build a verifier");
            let verifier = Arc::new(LoopbackOrWebpki { webpki });
            Arc::new(
                ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(verifier)
                    .with_no_client_auth(),
            )
        })
        .clone()
}

#[derive(Debug)]
struct LoopbackOrWebpki {
    webpki: Arc<dyn ServerCertVerifier>,
}

impl ServerCertVerifier for LoopbackOrWebpki {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        match self.webpki.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(verified) => Ok(verified),
            Err(err) if loopback(server_name) => {
                let _ = err;
                Ok(ServerCertVerified::assertion())
            }
            Err(err) => Err(err),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.webpki.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.webpki.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.webpki.supported_verify_schemes()
    }
}

fn loopback(name: &ServerName<'_>) -> bool {
    match name {
        ServerName::DnsName(dns) => dns.as_ref().eq_ignore_ascii_case("localhost"),
        ServerName::IpAddress(ip) => std::net::IpAddr::from(*ip).is_loopback(),
        _ => false,
    }
}

struct Parsed {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn parse_response(bytes: &[u8]) -> Result<Parsed, String> {
    let split = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| "the response had no header end".to_string())?;
    if split > MAX_HEADER {
        return Err("the response headers are too large".to_string());
    }
    let header_text = std::str::from_utf8(&bytes[..split])
        .map_err(|_| "the response headers are not UTF-8".to_string())?;
    let mut lines = header_text.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or("");
    if !version.starts_with("HTTP/1.") {
        return Err("the response is not HTTP/1".to_string());
    }
    let status = parts
        .next()
        .unwrap_or("")
        .parse()
        .map_err(|_| "the response status is not a number".to_string())?;
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| "a response header has no colon".to_string())?;
        headers.push((name.trim().to_string(), value.trim().to_string()));
    }
    let raw = &bytes[split + 4..];
    let body = if header_value(&headers, "transfer-encoding")
        .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"))
    {
        decode_chunks(raw)?
    } else if let Some(length) = header_value(&headers, "content-length") {
        let length: usize = length
            .parse()
            .map_err(|_| "Content-Length is not a number".to_string())?;
        if length > MAX_BODY || length > raw.len() {
            return Err("the response body is the wrong length".to_string());
        }
        raw[..length].to_vec()
    } else {
        raw.to_vec()
    };
    if body.len() > MAX_BODY {
        return Err("the response body is too large".to_string());
    }
    Ok(Parsed {
        status,
        headers,
        body,
    })
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(header, _)| header.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn decode_chunks(mut bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let line_end = bytes
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| "a chunk size line was cut off".to_string())?;
        let line = std::str::from_utf8(&bytes[..line_end])
            .map_err(|_| "a chunk size is not UTF-8".to_string())?;
        let size_text = line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| "a chunk size is not hex".to_string())?;
        bytes = &bytes[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        if size > MAX_BODY || bytes.len() < size + 2 {
            return Err("a chunk was cut off".to_string());
        }
        out.extend_from_slice(&bytes[..size]);
        if &bytes[size..size + 2] != b"\r\n" {
            return Err("a chunk did not end".to_string());
        }
        bytes = &bytes[size + 2..];
        if out.len() > MAX_BODY {
            return Err("the response body is too large".to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn get_and_post_round_trip_on_plain_http() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut buf = [0u8; 2048];
                let n = stream.read(&mut buf).unwrap();
                let text = String::from_utf8_lossy(&buf[..n]);
                let body = if text.starts_with("POST") {
                    "posted"
                } else {
                    "fetched"
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).unwrap();
            }
        });
        let got = exchange(
            "GET",
            &format!("http://127.0.0.1:{port}/.well-known/openid-credential-issuer"),
            None,
            None,
            &[],
        )
        .unwrap();
        assert_eq!(got.status, 200);
        assert_eq!(got.body, b"fetched");
        let posted = exchange(
            "POST",
            &format!("http://127.0.0.1:{port}/oauth2/token"),
            Some("application/x-www-form-urlencoded"),
            Some("access-1"),
            b"grant_type=x",
        )
        .unwrap();
        assert_eq!(posted.body, b"posted");
    }

    #[test]
    fn loopback_is_localhost_and_loopback_addresses() {
        let name = |text| ServerName::try_from(text).unwrap();
        assert!(loopback(&name("localhost")));
        assert!(loopback(&name("LocalHost")));
        assert!(!loopback(&name("issuer.example")));
        assert!(loopback(&name("127.0.0.1")));
        assert!(loopback(&name("::1")));
        assert!(!loopback(&name("8.8.8.8")));
    }

    #[test]
    fn loopback_issuer_metadata_when_requested() {
        if std::env::var("OID4VC_WALLET_SMOKE").is_err() {
            return;
        }
        let got = exchange(
            "GET",
            "https://localhost:8081/.well-known/openid-credential-issuer",
            None,
            None,
            &[],
        )
        .expect("issuer metadata");
        assert_eq!(got.status, 200);
        let body = String::from_utf8(got.body).expect("utf-8");
        assert!(body.contains("credential_endpoint"), "{body}");
        assert!(body.contains("nonce_endpoint"), "{body}");
    }
}
