use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use instant_acme::{
    Account, AccountCredentials, ChallengeType, Identifier,
    LetsEncrypt, NewAccount, NewOrder, RetryPolicy,
};
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use serde::{Deserialize, Serialize};
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::error::{Error, Result};
use crate::provider::{BackgroundGuard, CertProvider};

const DEFAULT_PROPAGATION_SECS: u64 = 60;
const DEFAULT_RENEW_WITHIN_DAYS: u64 = 30;

// ---------------------------------------------------------------------------
// DnsProvider trait
// ---------------------------------------------------------------------------

/// Implement this to plug in any DNS provider.
///
/// Both methods receive the fully-qualified `_acme-challenge.<domain>` name
/// and the TXT record value (the ACME key authorisation digest).
#[async_trait]
pub trait DnsProvider: Send + Sync + 'static {
    async fn add_txt_record(&self, fqdn: &str, value: &str) -> Result<()>;
    async fn remove_txt_record(&self, fqdn: &str, value: &str) -> Result<()>;
}

#[async_trait]
impl<T: DnsProvider> DnsProvider for Arc<T> {
    async fn add_txt_record(&self, fqdn: &str, value: &str) -> Result<()> {
        self.as_ref().add_txt_record(fqdn, value).await
    }

    async fn remove_txt_record(&self, fqdn: &str, value: &str) -> Result<()> {
        self.as_ref().remove_txt_record(fqdn, value).await
    }
}

// ---------------------------------------------------------------------------
// BunnyDns
// ---------------------------------------------------------------------------

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct BunnyZone {
    id: u64,
    domain: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct BunnyZoneList {
    items: Vec<BunnyZone>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct BunnyRecord {
    id: u64,
    name: String,
    value: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct BunnyZoneDetail {
    dns_records: Vec<BunnyRecord>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct BunnyAddRecord<'a> {
    #[serde(rename = "Type")]
    record_type: u8,
    name: &'a str,
    value: &'a str,
    ttl: u32,
}

/// DNS-01 provider backed by the bunny.net DNS API.
///
/// Obtain an API key from the bunny.net dashboard -> Account -> API.
pub struct BunnyDns {
    api_key: String,
    client: reqwest::Client,
}

impl BunnyDns {
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            client: reqwest::Client::new(),
        }
    }

    fn base(&self) -> &str {
        "https://api.bunny.net"
    }

    async fn find_zone(&self, fqdn: &str) -> Result<(u64, String)> {
        let name = fqdn.trim_end_matches('.');
        let parts: Vec<&str> = name.split('.').collect();
        for i in 0..parts.len().saturating_sub(1) {
            let candidate = parts[i..].join(".");
            let url = format!("{}/dnszone?search={}&page=1&perPage=10", self.base(), candidate);
            let resp = self
                .client
                .get(&url)
                .header("AccessKey", &self.api_key)
                .header("accept", "application/json")
                .send()
                .await
                .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;

            if !resp.status().is_success() {
                continue;
            }
            let list: BunnyZoneList = resp.json().await.map_err(|e| {
                Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
            })?;
            for zone in list.items {
                if name.ends_with(&zone.domain) {
                    return Ok((zone.id, zone.domain));
                }
            }
        }
        Err(Error::Config(format!(
            "bunny.net: no DNS zone found for {fqdn}"
        )))
    }

    fn relative_name<'a>(&self, fqdn: &'a str, zone_domain: &str) -> &'a str {
        let name = fqdn.trim_end_matches('.');
        name.strip_suffix(&format!(".{zone_domain}"))
            .or_else(|| name.strip_suffix(zone_domain))
            .unwrap_or(name)
    }
}

#[async_trait]
impl DnsProvider for BunnyDns {
    async fn add_txt_record(&self, fqdn: &str, value: &str) -> Result<()> {
        let (zone_id, zone_domain) = self.find_zone(fqdn).await?;
        let record_name = self.relative_name(fqdn, &zone_domain);

        let body = BunnyAddRecord {
            record_type: 3,
            name: record_name,
            value,
            ttl: 120,
        };

        let url = format!("{}/dnszone/{zone_id}/records", self.base());
        let resp = self
            .client
            .put(&url)
            .header("AccessKey", &self.api_key)
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(Error::Config(format!(
                "bunny.net: add TXT record failed ({status}): {text}"
            )));
        }
        info!("bunny.net: added TXT {fqdn} = {value}");
        Ok(())
    }

    async fn remove_txt_record(&self, fqdn: &str, value: &str) -> Result<()> {
        let (zone_id, zone_domain) = self.find_zone(fqdn).await?;
        let record_name = self.relative_name(fqdn, &zone_domain);

        let url = format!("{}/dnszone/{zone_id}", self.base());
        let resp = self
            .client
            .get(&url)
            .header("AccessKey", &self.api_key)
            .header("accept", "application/json")
            .send()
            .await
            .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;

        if !resp.status().is_success() {
            let status = resp.status();
            return Err(Error::Config(format!(
                "bunny.net: fetch zone failed ({status})"
            )));
        }

        let detail: BunnyZoneDetail = resp.json().await.map_err(|e| {
            Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
        })?;

        for record in detail.dns_records {
            if record.name == record_name && record.value == value {
                let del_url = format!("{}/dnszone/{zone_id}/records/{}", self.base(), record.id);
                let del_resp = self
                    .client
                    .delete(&del_url)
                    .header("AccessKey", &self.api_key)
                    .send()
                    .await
                    .map_err(|e| {
                        Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
                    })?;
                if del_resp.status().is_success() {
                    info!("bunny.net: removed TXT {fqdn} (id={})", record.id);
                } else {
                    let status = del_resp.status();
                    warn!("bunny.net: delete record {} failed ({status})", record.id);
                }
                return Ok(());
            }
        }
        warn!("bunny.net: TXT record {fqdn}={value} not found for cleanup");
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Credential caching
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct CachedCredentials {
    credentials: AccountCredentials,
}

async fn load_or_create_account(
    cache_dir: &Path,
    email: &str,
    production: bool,
) -> Result<Account> {
    let creds_path = cache_dir.join("acme_account_credentials.json");

    if creds_path.exists() {
        let json = tokio::fs::read_to_string(&creds_path).await?;
        if let Ok(cached) = serde_json::from_str::<CachedCredentials>(&json) {
            let builder = Account::builder()
                .map_err(|e| Error::AcmeProtocol(e.to_string()))?;
            match builder.from_credentials(cached.credentials).await {
                Ok(account) => {
                    info!("Loaded ACME account from cache");
                    return Ok(account);
                }
                Err(e) => {
                    warn!("Cached ACME credentials invalid ({e}), creating new account");
                }
            }
        }
    }

    let builder = Account::builder()
        .map_err(|e| Error::AcmeProtocol(e.to_string()))?;

    let contact = format!("mailto:{email}");
    let server = if production {
        LetsEncrypt::Production.url().to_string()
    } else {
        LetsEncrypt::Staging.url().to_string()
    };

    let new_account = NewAccount {
        contact: &[contact.as_str()],
        terms_of_service_agreed: true,
        only_return_existing: false,
    };
    let (account, credentials) = builder
        .create(&new_account, server, None)
        .await
        .map_err(|e| Error::AcmeProtocol(e.to_string()))?;

    let cached = CachedCredentials { credentials };
    let json = serde_json::to_string_pretty(&cached)
        .map_err(|e| Error::Config(format!("serialize account credentials: {e}")))?;
    tokio::fs::write(&creds_path, json).await?;
    info!("Created and cached new ACME account");
    Ok(account)
}

// ---------------------------------------------------------------------------
// CSR generation
// ---------------------------------------------------------------------------

fn generate_csr(domains: &[String]) -> Result<(Vec<u8>, Vec<u8>)> {
    let key_pair = KeyPair::generate()
        .map_err(|e| Error::Config(format!("CSR key gen: {e}")))?;

    let mut params = CertificateParams::new(domains.to_vec())
        .map_err(|e| Error::Config(format!("CSR params: {e}")))?;
    params.distinguished_name = DistinguishedName::new();

    let csr = params
        .serialize_request(&key_pair)
        .map_err(|e| Error::Config(format!("CSR serialize: {e}")))?;

    let csr_der = csr.der().to_vec();
    let key_pem = key_pair.serialize_pem().into_bytes();
    Ok((csr_der, key_pem))
}

// ---------------------------------------------------------------------------
// Cert expiry parsing
// ---------------------------------------------------------------------------

fn read_cert_not_after(fullchain_path: &Path) -> Result<SystemTime> {
    let pem_bytes = std::fs::read(fullchain_path).map_err(Error::Io)?;

    let (_, pem) = parse_x509_pem(&pem_bytes)
        .map_err(|e| Error::Config(format!("cert PEM parse: {e}")))?;

    let (_, cert) = X509Certificate::from_der(&pem.contents)
        .map_err(|e| Error::Config(format!("cert DER parse: {e}")))?;

    let ts = cert.validity().not_after.timestamp();
    if ts < 0 {
        return Err(Error::Config("cert NotAfter is before Unix epoch".into()));
    }
    Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(ts as u64))
}

// ---------------------------------------------------------------------------
// DNS-01 issuance flow
// ---------------------------------------------------------------------------

struct ChallengeInfo {
    fqdn: String,
    dns_value: String,
}

async fn issue_certificate<D: DnsProvider>(
    dns: &D,
    account: &Account,
    domains: &[String],
    propagation_secs: u64,
    cert_dir: &Path,
) -> Result<()> {
    let identifiers: Vec<Identifier> = domains.iter().map(|d| Identifier::Dns(d.clone())).collect();
    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .map_err(|e| Error::AcmeProtocol(e.to_string()))?;

    // Phase 1: iterate authorizations and add TXT records
    let mut challenge_info: Vec<ChallengeInfo> = Vec::new();
    {
        let mut authorizations = order.authorizations();
        while let Some(authz_result) = authorizations.next().await {
            let mut authz = authz_result.map_err(|e| Error::AcmeProtocol(e.to_string()))?;

            if authz.status == instant_acme::AuthorizationStatus::Valid {
                continue;
            }

            let domain = match authz.identifier().identifier {
                Identifier::Dns(ref d) => d.clone(),
                _ => return Err(Error::Config("non-DNS identifier".into())),
            };

            let Some(challenge) = authz.challenge(ChallengeType::Dns01) else {
                return Err(Error::Challenge("no DNS-01 challenge offered".into()));
            };

            let key_auth = challenge.key_authorization();
            let dns_value = key_auth.dns_value();
            let fqdn = format!("_acme-challenge.{domain}");

            dns.add_txt_record(&fqdn, &dns_value).await?;
            challenge_info.push(ChallengeInfo { fqdn, dns_value });
        }
    }

    // Wait for DNS propagation
    if !challenge_info.is_empty() {
        info!(
            "DNS-01: waiting {}s for TXT propagation",
            propagation_secs
        );
        sleep(Duration::from_secs(propagation_secs)).await;
    }

    // Phase 2: signal challenges ready (second pass uses cached authorizations,
    // no network calls)
    {
        let mut authorizations = order.authorizations();
        while let Some(authz_result) = authorizations.next().await {
            let mut authz = authz_result.map_err(|e| Error::AcmeProtocol(e.to_string()))?;

            if authz.status == instant_acme::AuthorizationStatus::Valid {
                continue;
            }

            let Some(mut challenge) = authz.challenge(ChallengeType::Dns01) else {
                continue;
            };

            challenge
                .set_ready()
                .await
                .map_err(|e| Error::AcmeProtocol(e.to_string()))?;
        }
    }

    // Poll until order ready
    let retry_policy = RetryPolicy::default();
    order
        .poll_ready(&retry_policy)
        .await
        .map_err(|e| Error::AcmeProtocol(e.to_string()))?;

    // Finalize: generate CSR and submit
    let (csr_der, key_pem) = generate_csr(domains)?;
    order
        .finalize_csr(&csr_der)
        .await
        .map_err(|e| Error::AcmeProtocol(e.to_string()))?;

    // Poll until certificate available
    let cert_pem = order
        .poll_certificate(&retry_policy)
        .await
        .map_err(|e| Error::AcmeProtocol(e.to_string()))?;

    // Write PEM files
    let fullchain_path = cert_dir.join("fullchain.pem");
    let privkey_path = cert_dir.join("privkey.pem");
    tokio::fs::write(&fullchain_path, &cert_pem).await?;
    tokio::fs::write(&privkey_path, &key_pem).await?;
    info!("DNS-01 certificate written to {:?}", cert_dir);

    // Cleanup TXT records (best-effort)
    for ci in &challenge_info {
        if let Err(e) = dns.remove_txt_record(&ci.fqdn, &ci.dns_value).await {
            warn!("Failed to remove TXT record {}: {e}", ci.fqdn);
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// DnsAcmeProvider
// ---------------------------------------------------------------------------

/// ACME provider using DNS-01 challenges.
///
/// Suitable when you cannot open port 443 (e.g. on fly.io without a dedicated
/// IPv4). Requires programmatic access to your DNS provider.
///
/// # Usage
///
/// ```no_run
/// use cert_provider::provider::dns01::{DnsAcmeProvider, BunnyDns};
/// use cert_provider::provider::CertProvider;
///
/// let dns = BunnyDns::new(std::env::var("BUNNY_API_KEY").unwrap());
/// let mut provider = DnsAcmeProvider::new("admin@example.com", dns)
///     .production()
///     .propagation_secs(90);
///
/// let _guard = provider.init(cert_dir, Some(domains)).await?;
/// ```
pub struct DnsAcmeProvider<D: DnsProvider> {
    contact_email: String,
    dns: Arc<D>,
    production: bool,
    propagation_secs: u64,
    renew_within_days: u64,
}

impl<D: DnsProvider> DnsAcmeProvider<D> {
    /// Create a new provider backed by the given DNS implementation.
    ///
    /// Defaults to the Let's Encrypt **staging** environment.
    /// Call `.production()` before deploying for real.
    pub fn new(contact_email: impl Into<String>, dns: D) -> Self {
        Self {
            contact_email: contact_email.into(),
            dns: Arc::new(dns),
            production: false,
            propagation_secs: DEFAULT_PROPAGATION_SECS,
            renew_within_days: DEFAULT_RENEW_WITHIN_DAYS,
        }
    }

    /// Create a new provider with a pre-wrapped shared DNS backend.
    pub fn from_arc(contact_email: impl Into<String>, dns: Arc<D>) -> Self {
        Self {
            contact_email: contact_email.into(),
            dns,
            production: false,
            propagation_secs: DEFAULT_PROPAGATION_SECS,
            renew_within_days: DEFAULT_RENEW_WITHIN_DAYS,
        }
    }

    /// Switch to the Let's Encrypt **production** directory.
    pub fn production(mut self) -> Self {
        self.production = true;
        self
    }

    /// Seconds to wait after adding TXT records before notifying Let's Encrypt.
    /// Default: 60 s. Increase if your DNS has slow propagation.
    pub fn propagation_secs(mut self, secs: u64) -> Self {
        self.propagation_secs = secs;
        self
    }

    /// Number of days before certificate expiry at which to begin renewal.
    /// Default: 30 days (Let's Encrypt certs are valid for 90 days).
    pub fn renew_within_days(mut self, days: u64) -> Self {
        self.renew_within_days = days;
        self
    }
}

#[async_trait]
impl<D: DnsProvider> CertProvider for DnsAcmeProvider<D> {
    async fn init(
        &mut self,
        cert_dir: PathBuf,
        domains: Option<Vec<String>>,
    ) -> Result<BackgroundGuard> {
        let domains = domains.ok_or_else(|| Error::Config("domains required".into()))?;
        if domains.is_empty() {
            return Err(Error::Config("at least one domain required".into()));
        }

        tokio::fs::create_dir_all(&cert_dir).await?;
        let cache_dir = cert_dir.join("acme_cache");
        tokio::fs::create_dir_all(&cache_dir).await?;

        let fullchain_path = cert_dir.join("fullchain.pem");
        let privkey_path = cert_dir.join("privkey.pem");

        // Issue cert if missing
        if !fullchain_path.exists() || !privkey_path.exists() {
            let account = load_or_create_account(&cache_dir, &self.contact_email, self.production).await?;
            issue_certificate(
                &self.dns,
                &account,
                &domains,
                self.propagation_secs,
                &cert_dir,
            )
            .await?;
        } else {
            info!("Existing cert files found in {:?}", cert_dir);
        }

        // Spawn background renewal task
        let cancel = CancellationToken::new();
        let bg_cancel = cancel.clone();
        let dns = self.dns.clone();
        let bg_cert_dir = cert_dir.clone();
        let bg_cache_dir = cache_dir.clone();
        let contact_email = self.contact_email.clone();
        let bg_domains = domains.clone();
        let production = self.production;
        let propagation_secs = self.propagation_secs;
        let bg_renew_within = Duration::from_secs(self.renew_within_days * 86400);

        tokio::spawn(async move {
            let mut retry_delay = Duration::from_secs(3600);

            loop {
                // Compute how long to sleep until renewal is needed
                let next_renewal = read_cert_not_after(&bg_cert_dir.join("fullchain.pem"));
                let sleep_until = match next_renewal {
                    Ok(not_after) => {
                        retry_delay = Duration::from_secs(3600);
                        let renew_at = not_after
                            .checked_sub(bg_renew_within)
                            .unwrap_or(not_after);
                        renew_at
                            .duration_since(SystemTime::now())
                            .unwrap_or(Duration::ZERO)
                    }
                    Err(e) => {
                        warn!("Failed to read cert expiry: {e}, retrying in {:?}", retry_delay);
                        let d = retry_delay;
                        retry_delay = (retry_delay * 2).min(Duration::from_secs(86400));
                        d
                    }
                };

                // Sleep until renewal time (or retry), with cancellation
                tokio::select! {
                    biased;
                    _ = bg_cancel.cancelled() => {
                        info!("DNS-01 renewal loop stopped");
                        return;
                    }
                    _ = sleep(sleep_until) => {}
                }

                // Re-load account (refreshed from cache each time)
                let account = match load_or_create_account(&bg_cache_dir, &contact_email, production).await {
                    Ok(a) => a,
                    Err(e) => {
                        warn!("Renewal: account load failed ({e}), retrying in {:?}", retry_delay);
                        tokio::select! {
                            biased;
                            _ = bg_cancel.cancelled() => return,
                            _ = sleep(retry_delay) => {}
                        }
                        retry_delay = (retry_delay * 2).min(Duration::from_secs(86400));
                        continue;
                    }
                };

                // Attempt renewal
                match issue_certificate(&dns, &account, &bg_domains, propagation_secs, &bg_cert_dir).await {
                    Ok(()) => {
                        info!("DNS-01 certificate renewed successfully");
                        retry_delay = Duration::from_secs(3600);
                    }
                    Err(e) => {
                        warn!("Renewal failed: {e}, retrying in {:?}", retry_delay);
                        tokio::select! {
                            biased;
                            _ = bg_cancel.cancelled() => return,
                            _ = sleep(retry_delay) => {}
                        }
                        retry_delay = (retry_delay * 2).min(Duration::from_secs(86400));
                    }
                }
            }
        });

        Ok(BackgroundGuard::new(cancel))
    }
}
