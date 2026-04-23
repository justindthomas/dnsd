//! DNS-over-HTTPS listener — `axum` over `tokio-rustls` over
//! `VclStream`, with `rustls-acme` demultiplexing tls-alpn-01
//! challenges at the handshake layer. Populated in task #10.
