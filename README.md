# cert-provider

`cert-provider` is a Rust library crate that provides a unified, async interface for automatic TLS certificate provisioning and renewal using the ACME protocol. It abstracts over two popular ACME backends, allowing you to embed “certbot-like” functionality entirely within your application.

The crate guarantees that valid certificate and key files are present in a given directory before your TLS server starts, and it keeps them renewed for as long as you hold onto the returned guard.

---

## Features

- **Two backends** (selectable via Cargo features):
  - `tokio-acme` – uses [`tokio-rustls-acme`], a deeply integrated, high‑level provider that handles everything inside the TLS stack and uses `TLS-ALPN-01` challenges.
  - `rfc8555` – uses [`acme-rfc8555`], a more explicit ACME client that gives you full control; the implementation uses `HTTP-01` challenges.
- **Uniform API** – both backends implement the `CertProvider` trait, so swapping them is a one‑line change.
- **Persistent caching** – ACME account keys and orders survive restarts, avoiding rate‑limit issues.
- **Background renewal** – a spawned task automatically renews certificates well before expiry.
- **Minimal intrusion** – you still own your TLS server; the crate only writes the PEM files and returns a guard handle.

---

## Installation

Add `cert-provider` to your `Cargo.toml`, enabling the feature for the backend you want:

```toml
[dependencies]
cert-provider = { version = "0.1", features = ["tokio-acme"] }
# or
cert-provider = { version = "0.1", features = ["rfc8555"] }
```

---

## Quick Start

```rust
use cert_provider::CertProvider;
use cert_provider::providers::tokio_acme::TokioAcmeProvider; // or rfc8555::AcmeRfc8555Provider

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Choose a provider (here the all‑in‑one tokio-acme variant).
    let provider: Box<dyn CertProvider> = Box::new(TokioAcmeProvider::new("admin@example.com"));

    // 2. Initialize. This writes fullchain.pem and privkey.pem into `/etc/certs`.
    //    The guard keeps background renewal alive.
    let _guard = provider.init(
        "/etc/certs".into(),
        Some(vec!["myapp.example.com".into()]),
    ).await?;

    // 3. Load the PEM files and configure your TLS server (rustls, etc.).
    //    Your server can now start, knowing the cert is ready.
    // ...

    // 4. Keep the guard alive for the process lifetime (it cancels renewal on drop).
    println!("Certificate ready, starting server...");
    // ... run your server indefinitely ...
    Ok(())
}
```

The `init` method blocks until a valid certificate is obtained, so you can safely start your TLS server immediately after it returns.

---

## Provider Details & Port Requirements

Both backends require your application to be reachable on certain ports for ACME challenge validation. The exact requirements depend on the provider and your deployment environment.

### `tokio-acme` (feature `tokio-acme`)
- **Challenge type:** `TLS-ALPN-01`.
- **How it works:** During initial issuance, the library binds a **temporary loopback listener** and completes a self‑TLS handshake to trigger the ACME flow. No additional external port is needed aside from the main HTTPS port (443).
- **Deployment:** You only need to expose port 443. The library obtains the certificate using ALPN directly on your TLS server when a real client connects, but the crate’s `init` uses the loopback trick to get the first certificate *before* your server starts. No separate HTTP port is required.

### `rfc8555` (feature `rfc8555`)
- **Challenge type:** `HTTP-01`.
- **How it works:** The provider starts a **temporary HTTP server on port 80** (configurable) to answer ACME challenges. The Let's Encrypt validation server must be able to reach your app on port 80.
- **Deployment:** You must expose port **80** in addition to 443. The HTTP server only runs during initial certificate acquisition and periodically during renewal (a few seconds). It automatically shuts down afterwards.

> **Note:** You can use the `LETS_ENCRYPT_STAGING` URL during development to avoid rate limits. Both providers offer a staging constructor (e.g., `AcmeRfc8555Provider::staging(...)`).

---

## Deployment on Fly.io (TCP passthrough)

Because `cert-provider` terminates TLS itself, you must configure Fly to forward raw TCP to your app, without any TLS termination by the edge proxy. The following `fly.toml` examples show how to open the required ports.

### For `tokio-acme` (only port 443 needed)

```toml
app = "myapp"

[build]
  image = "."

[[services]]
  internal_port = 443
  protocol = "tcp"
  auto_stop_machines = "stop"
  auto_start_machines = true
  min_machines_running = 1

  [[services.ports]]
    port = 443
    handlers = []          # raw TCP, no TLS termination
```

Your Rust application must listen on `0.0.0.0:443` (or another port mapped via `internal_port`). The `cert-provider` init will handle obtaining the certificate using the loopback trick – no special port 80 is required.

### For `rfc8555` (ports 80 and 443)

```toml
app = "myapp"

[[services]]
  internal_port = 443
  protocol = "tcp"
  auto_stop_machines = "stop"
  auto_start_machines = true
  min_machines_running = 1

  [[services.ports]]
    port = 443
    handlers = []

[[services]]
  internal_port = 80
  protocol = "tcp"
  auto_stop_machines = "stop"
  auto_start_machines = true
  min_machines_running = 1

  [[services.ports]]
    port = 80
    handlers = []
```

Your application must listen on both ports: `0.0.0.0:443` for your main TLS server and `0.0.0.0:80` for the temporary ACME HTTP challenge server (which the `rfc8555` provider will bind).

> **Important:** Because you are bypassing Fly’s edge, you must **own a custom domain** (not `*.fly.dev`) to provision Let's Encrypt certificates – the `*.fly.dev` wildcard is only available through Fly's built‑in HTTP proxy. Point your custom domain’s DNS to your Fly app’s IPv4/IPv6 address.

---

## File Layout

After a successful `init`, the `cert_dir` will contain:

```
/etc/certs/
├── fullchain.pem          # certificate chain
├── privkey.pem            # private key
└── cache/                 # persistent ACME account & order data (do not delete)
```

Your application can simply load these files and pass them to `rustls::ServerConfig` or any TLS library that accepts PEM-encoded certificates.

---

## API Reference

The main trait lives in `cert_provider::CertProvider`:

```rust
#[async_trait]
pub trait CertProvider: Send + Sync + 'static {
    async fn init(
        self: Box<Self>,
        cert_dir: PathBuf,
        domains: Option<Vec<String>>,
    ) -> Result<BackgroundGuard, Error>;
}
```

- `cert_dir` – writable directory where `fullchain.pem` and `privkey.pem` will be stored.
- `domains` – list of SANs for the certificate (e.g., `["example.com", "www.example.com"]`). `None` will cause an error – this is a mandatory parameter.
- Returns `BackgroundGuard` – a handle that cancels the background renewal task when dropped. Keep it alive for the duration of your process.

---

## Error Handling

All errors are instances of `cert_provider::Error`, a non‑exhaustive enum that captures common failure modes (`Io`, `AcmeProtocol`, `Challenge`, `Config`, etc.). You can match on these variants or convert them to your application’s error type.

---

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.

---

[`tokio-rustls-acme`]: https://crates.io/crates/tokio-rustls-acme
[`acme-rfc8555`]: https://crates.io/crates/acme-rfc8555