use color_eyre::Report;
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::{
    rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore},
    TlsConnector,
};
use tracing::info;
use tracing_subscriber::EnvFilter;

mod tj;

// set up single thread
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Report> {
    setup()?;

    info!("Joining...");
    let res = tj::try_join(fetch_thing("first"), fetch_thing("second")).await?;
    info!(?res, "All done!");

    Ok(())
}

#[allow(dead_code)]
async fn fetch_thing(name: &str) -> Result<&str, Report> {
    let addr: SocketAddr = ([14, 215, 177, 38], 443).into();
    let socket = TcpStream::connect(addr).await?;

    let mut root_store = RootCertStore::empty();
    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));
    let connector: TlsConnector = {
        let config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        Arc::new(config).into()
    };
    let dnsname = "www.baidu.com".try_into().expect("fail parse server name");
    let mut socket = connector.connect(dnsname, socket).await?;

    socket.write_all(b"GET / HTTP/1.1\r\n").await?;
    socket.write_all(b"Host: www.baidu.com\r\n").await?;
    socket.write_all(b"User-Agent: rust\r\n").await?;
    socket.write_all(b"Connection: close\r\n").await?;
    socket.write_all(b"\r\n").await?;

    let mut response = String::with_capacity(256);
    socket.read_to_string(&mut response).await?;

    let status = response.lines().next().unwrap_or_default();
    info!(%status, %name, "Got response!");

    // dropping the socket will close the connection

    Ok(name)
}

fn setup() -> Result<(), Report> {
    if std::env::var("RUST_LIB_BACKTRACE").is_err() {
        std::env::set_var("RUST_LIB_BACKTRACE", "1")
    }
    color_eyre::install()?;

    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info")
    }
    tracing_subscriber::fmt::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    Ok(())
}
