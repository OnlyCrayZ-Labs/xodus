// MSFS 2024 compatibility modifications: 2026-10-22; see PUBLICATION-PROVENANCE.md.
//! Title-scoped Xbox Live profile and tokens for the GDK bridge (version 3).
//!
//! The requesting title's own MSA app ID and title ID drive the Windows SISU
//! flow (`xodus::auth::do_sisu`) with the account and device already
//! authenticated by this service. Relying parties and signature policies come
//! from Microsoft's title endpoint list. As on Windows, the title receives its
//! XSTS authorization header and request signature; MSA, device, title and user
//! tokens stay in this service. Only outcomes are logged, never token data.
use std::collections::HashMap;
use std::sync::LazyLock;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use xodus::xal::response::{DeviceToken, SisuRPSAuthorizationResponse, XSTSToken};
use xodus::xal::{RequestSigner, XalAuthenticator};

use crate::simple_context::SimpleContext;

pub const VERSION: u32 = 3;
const MAX_REQUEST: usize = 32 << 20;
const OP_PROFILE: u32 = 1;
const OP_TOKEN: u32 = 2;
const OP_SECURITY: u32 = 3;
const OP_COLLECTIONS: u32 = 4;
const OP_ENTITLED_PRODUCTS: u32 = 5;
const OP_LICENSE_TOKEN: u32 = 6;
const OP_PACKAGE_UPDATE: u32 = 7;
const MAX_DEVELOPER_STRING: usize = 4096;
const CATALOG_BATCH: usize = 20;
const MAX_PRODUCT_IDS: u32 = 64;
/// WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3.
const TLS_PROTOCOLS: u32 = 0x800 | 0x2000;
const MAX_THUMBPRINTS: usize = 16;
const FORCE_REFRESH: u32 = 1;
const INVALID_ARG: u32 = 0x80070057;
const AUTH_FAILED: u32 = 0x89245111;
const TIMEOUT: u32 = 0x800705b4;

struct Session {
    auth: XalAuthenticator,
    /// Shares the device proof key bound to `device`; caches title endpoints.
    signer: RequestSigner,
    device: DeviceToken,
    sisu: SisuRPSAuthorizationResponse,
    xsts: HashMap<String, XSTSToken>,
    /// Authenticated title NSAL; discarded with the SISU session on refresh.
    title_endpoints: Option<xodus::xal::response::TitleEndpointsResponse>,
}

static SESSIONS: LazyLock<tokio::sync::Mutex<HashMap<(String, u32), Session>>> =
    LazyLock::new(Default::default);

/// Relying party of the SISU authorization token issued with the title sign-in.
const SISU_RELYING_PARTY: &str = "http://xboxlive.com";

/// Error text for diagnostics only; xal errors carry status and XErr, not tokens.
fn describe(err: impl std::fmt::Display) -> String {
    err.to_string().chars().take(300).collect()
}

/// Xbox Live `Signature` header value: base64 of policy version (i32 BE),
/// FILETIME (u64 BE) and the P-256 ECDSA signature over xal's prehash of
/// version, time, method, path and query, authorization and body. Computed
/// here because xal's `RequestSigning<http::Request>` drops the headers of the
/// request it returns, including `Signature`.
fn sign(
    signer: &RequestSigner,
    policy: &xodus::xal::SigningPolicy,
    method: &str,
    url: &str,
    authorization: &str,
    body: &[u8],
) -> Result<String, String> {
    use base64ct::Encoding;
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    let url = xodus::xal::url::Url::parse(url).map_err(describe)?;
    let path_and_query = match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_owned(),
    };
    let now = chrono::Utc::now();
    let filetime = (now.timestamp() + 11_644_473_600) as u64 * 10_000_000
        + u64::from(now.timestamp_subsec_nanos() / 100);
    let version = policy.version.to_be_bytes();
    let time = filetime.to_be_bytes();
    let prehash = RequestSigner::prehash_message_data(
        &version,
        &time,
        method,
        &path_and_query,
        authorization,
        body,
        policy.max_body_bytes,
    );
    let key = p256::ecdsa::SigningKey::from(signer.keypair.clone());
    let signature: p256::ecdsa::Signature = key.sign_prehash(&prehash).map_err(describe)?;
    let mut bytes = version.to_vec();
    bytes.extend_from_slice(&time);
    bytes.extend_from_slice(&signature.to_bytes());
    Ok(base64ct::Base64::encode_string(&bytes))
}

fn fresh(not_after: chrono::DateTime<chrono::Utc>) -> bool {
    not_after - chrono::Duration::minutes(5) > chrono::Utc::now()
}

impl Session {
    fn valid(&self) -> bool {
        fresh(self.device.not_after)
            && fresh(self.sisu.title_token.not_after)
            && fresh(self.sisu.user_token.not_after)
            && fresh(self.sisu.authorization_token.not_after)
    }

    fn claims(&self) -> Option<&HashMap<String, String>> {
        self.sisu
            .authorization_token
            .display_claims
            .as_ref()?
            .xui
            .first()
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], u32> {
        let (head, tail) = self.0.split_at_checked(n).ok_or(INVALID_ARG)?;
        self.0 = tail;
        Ok(head)
    }
    fn u32(&mut self) -> Result<u32, u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn bytes(&mut self) -> Result<&'a [u8], u32> {
        let n = self.u32()? as usize;
        self.take(n)
    }
    fn str(&mut self) -> Result<&'a str, u32> {
        std::str::from_utf8(self.bytes()?).map_err(|_| INVALID_ARG)
    }
}

fn put(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

enum Request<'a> {
    Profile,
    Collections {
        products: Vec<&'a str>,
        kinds: u32,
        valid_only: bool,
    },
    EntitledProducts {
        store_id: &'a str,
        kinds: u32,
    },
    LicenseToken {
        store_id: &'a str,
        products: Vec<&'a str>,
        developer: &'a str,
    },
    PackageUpdate {
        store_id: &'a str,
        installed: &'a str,
    },
    Security {
        url: &'a str,
    },
    Token {
        force: bool,
        method: &'a str,
        url: &'a str,
        body: &'a [u8],
    },
}

fn valid_store_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 16 && id.bytes().all(|c| c.is_ascii_alphanumeric())
}

/// Request: u32 op, str MSA app ID, u32 title ID, then for tokens:
/// u32 options, str method, str URL, bytes body. Strings are u32-length UTF-8.
fn parse(payload: &[u8]) -> Result<(String, u32, Request<'_>), u32> {
    let mut r = Reader(payload);
    let op = r.u32()?;
    let app = r.str()?;
    let title = r.u32()?;
    if app.is_empty()
        || app.len() > 64
        || !app.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
        || title == 0
    {
        return Err(INVALID_ARG);
    }
    let request = match op {
        OP_PROFILE => Request::Profile,
        OP_SECURITY => Request::Security { url: r.str()? },
        OP_PACKAGE_UPDATE => {
            let store_id = r.str()?;
            let installed = r.str()?;
            if !valid_store_id(store_id) || parse_version(installed).is_none() {
                return Err(INVALID_ARG);
            }
            Request::PackageUpdate { store_id, installed }
        }
        OP_LICENSE_TOKEN => {
            let store_id = r.str()?;
            let count = r.u32()?;
            if !valid_store_id(store_id) || count > MAX_PRODUCT_IDS {
                return Err(INVALID_ARG);
            }
            let mut products = Vec::new();
            for _ in 0..count {
                let id = r.str()?;
                if !valid_store_id(id) {
                    return Err(INVALID_ARG);
                }
                products.push(id);
            }
            let developer = r.str()?;
            if developer.len() > MAX_DEVELOPER_STRING {
                return Err(INVALID_ARG);
            }
            Request::LicenseToken { store_id, products, developer }
        }
        OP_ENTITLED_PRODUCTS => {
            let store_id = r.str()?;
            if !valid_store_id(store_id) {
                return Err(INVALID_ARG);
            }
            Request::EntitledProducts { store_id, kinds: r.u32()? }
        }
        OP_COLLECTIONS => {
            let count = r.u32()?;
            if count > MAX_PRODUCT_IDS {
                return Err(INVALID_ARG);
            }
            let mut products = Vec::new();
            for _ in 0..count {
                let id = r.str()?;
                if id.is_empty() || id.len() > 32 || !id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'/') {
                    return Err(INVALID_ARG);
                }
                products.push(id);
            }
            Request::Collections {
                products,
                kinds: r.u32()?,
                valid_only: r.u32()? != 0,
            }
        }
        OP_TOKEN => Request::Token {
            force: r.u32()? & FORCE_REFRESH != 0,
            method: r.str()?,
            url: r.str()?,
            body: r.bytes()?,
        },
        _ => return Err(INVALID_ARG),
    };
    if !r.0.is_empty() {
        return Err(INVALID_ARG);
    }
    Ok((app.to_owned(), title, request))
}

async fn sign_in(context: &SimpleContext, app: &str, title: u32) -> Result<Session, u32> {
    let (auth, sisu, device) =
        xodus::auth::do_sisu(&context.client, context.tokens(), app, title.into())
            .await
            .map_err(|err| {
                tracing::warn!("Title sign-in failed: {}", describe(err));
                AUTH_FAILED
            })?;
    let signer = auth.request_signer();
    let mut session = Session {
        auth,
        signer,
        device,
        sisu,
        xsts: HashMap::new(),
        title_endpoints: None,
    };
    load_title_endpoints(&context.client, &mut session, title).await?;
    Ok(session)
}

/// Response: u64 XUID, then str gtg, mgt, mgs, umg, prv from the title XSTS claims.
fn profile(session: &Session) -> Result<Vec<u8>, u32> {
    let claims = session.claims().ok_or(AUTH_FAILED)?;
    let xid = claims
        .get("xid")
        .and_then(|x| x.parse::<u64>().ok())
        .filter(|&x| x != 0)
        .ok_or(AUTH_FAILED)?;
    let mut out = xid.to_le_bytes().to_vec();
    for key in ["gtg", "mgt", "mgs", "umg", "prv"] {
        put(&mut out, claims.get(key).map(String::as_bytes).unwrap_or_default());
    }
    Ok(out)
}

/// Resolve authorization and signing together from the winning endpoint.
/// Title entries win equal-specificity ties; catch-alls never shadow a more
/// specific default. Policy indices belong to their own list, never the other.
fn endpoint_authorization(
    title: Option<&xodus::xal::response::TitleEndpointsResponse>,
    defaults: &xodus::xal::response::TitleEndpointsResponse,
    url: &str,
) -> Result<(Option<String>, Option<xodus::xal::SigningPolicy>), u32> {
    let mut url = xodus::xal::url::Url::parse(url).map_err(|_| INVALID_ARG)?;
    match url.scheme() {
        "wss" => drop(url.set_scheme("https")),
        "ws" => drop(url.set_scheme("http")),
        "http" | "https" => {}
        _ => return Err(INVALID_ARG),
    }
    let host = url.host_str().ok_or(INVALID_ARG)?.to_ascii_lowercase();
    let winner = std::iter::once((defaults, false))
        .chain(title.map(|list| (list, true)))
        .flat_map(|(list, is_title)| list.end_points.iter().map(move |e| (list, is_title, e)))
        .filter(|(_, _, e)| {
            let pattern = e.host.to_ascii_lowercase();
            e.protocol.eq_ignore_ascii_case(url.scheme())
                && match e.host_type.as_str() {
                    "fqdn" => host == pattern,
                    "wildcard" => pattern.strip_prefix('*').is_some_and(|suffix| {
                        !suffix.contains('*') && host.ends_with(suffix)
                    }),
                    _ => false,
                }
                && e.path.as_ref().is_none_or(|path| url.path() == path)
        })
        .max_by_key(|(_, is_title, e)| (e.host.chars().filter(|&c| c != '*').count(), *is_title));
    let Some((list, _, endpoint)) = winner else { return Ok((None, None)); };
    let policy = endpoint.signature_policy_index.map(|index| {
        usize::try_from(index).ok().and_then(|i| list.signature_policies.get(i))
            .cloned().ok_or(AUTH_FAILED)
    }).transpose()?;
    Ok((endpoint.relying_party.clone(), policy))
}

/// Bootstrap against the standard list using title SISU XSTS + signature.
/// Do not use the title NSAL to authorize its own retrieval. Failure is an
/// authentication failure, never a silent fallback to empty backend tokens.
async fn load_title_endpoints(
    client: &reqwest::Client,
    session: &mut Session,
    title: u32,
) -> Result<(), u32> {
    if session.title_endpoints.is_some() { return Ok(()); }
    let url = format!("https://title.mgt.xboxlive.com/titles/{title}/endpoints");
    let (authorization, signature) = authorize(session, false, "GET", &url, b"").await?;
    if authorization.is_empty() || signature.is_empty() { return Err(AUTH_FAILED); }
    let response = client.get(&url)
        .header("x-xbl-contract-version", "1")
        .header("Authorization", authorization)
        .header("Signature", signature)
        .timeout(std::time::Duration::from_secs(20))
        .send().await.map_err(|_| {
            tracing::warn!("Authenticated title NSAL request failed");
            AUTH_FAILED
        })?;
    session.title_endpoints = Some(decode_title_endpoints(response).await?);
    Ok(())
}

async fn decode_title_endpoints(
    mut response: reqwest::Response,
) -> Result<xodus::xal::response::TitleEndpointsResponse, u32> {
    if !response.status().is_success() {
        tracing::warn!("Authenticated title NSAL returned HTTP {}", response.status());
        return Err(AUTH_FAILED);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| AUTH_FAILED)? {
        if body.len() + chunk.len() > 1 << 20 { return Err(AUTH_FAILED); }
        body.extend_from_slice(&chunk);
    }
    parse_title_endpoints(response.status(), &body)
}

fn parse_title_endpoints(
    status: reqwest::StatusCode,
    body: &[u8],
) -> Result<xodus::xal::response::TitleEndpointsResponse, u32> {
    if !status.is_success() || body.len() > 1 << 20 { return Err(AUTH_FAILED); }
    let list: xodus::xal::response::TitleEndpointsResponse =
        serde_json::from_slice(body).map_err(|_| AUTH_FAILED)?;
    if list.end_points.is_empty() { return Err(AUTH_FAILED); }
    Ok(list)
}

/// Response: str authorization header value, str signature. Both are empty for
/// URLs that have no Xbox Live relying party; the signature is empty when the
/// endpoint has no signature policy.
/// Authorization header value and Signature header value for a request.
async fn authorize(
    session: &mut Session,
    force: bool,
    method: &str,
    url: &str,
    body: &[u8],
) -> Result<(String, String), u32> {
    let defaults = endpoints().await?;
    let (relying_party, policy) = endpoint_authorization(
        session.title_endpoints.as_ref(), &defaults, url,
    )?;
    let Some(relying_party) = relying_party else {
        return Ok((String::new(), String::new()));
    };
    if relying_party == SISU_RELYING_PARTY {
        // The title sign-in (renewed by process() on ForceRefresh) already
        // issued this relying party's token.
        session
            .xsts
            .insert(relying_party.clone(), session.sisu.authorization_token.clone());
    } else if force || !session.xsts.get(&relying_party).is_some_and(|t| fresh(t.not_after)) {
        let xsts = session
            .auth
            .get_xsts_token(
                Some(&session.device),
                Some(&session.sisu.title_token),
                Some(&session.sisu.user_token),
                &relying_party,
            )
            .await
            .map_err(|err| {
                tracing::warn!("XSTS authorization failed for {relying_party}: {}", describe(err));
                AUTH_FAILED
            })?;
        session.xsts.insert(relying_party.clone(), xsts);
    }
    let xsts = &session.xsts[&relying_party];
    let uhs = xsts
        .display_claims
        .as_ref()
        .and_then(|c| c.xui.first())
        .and_then(|c| c.get("uhs"))
        .ok_or_else(|| {
            tracing::warn!("XSTS token for {relying_party} has no user hash claim");
            AUTH_FAILED
        })?;
    let authorization = format!("XBL3.0 x={uhs};{}", xsts.token);
    let signature = match policy {
        None => String::new(),
        Some(policy) => sign(&session.signer, &policy, method, url, &authorization, body).map_err(|err| {
            tracing::warn!("Request signing failed: {err}");
            INVALID_ARG
        })?,
    };
    Ok((authorization, signature))
}

async fn token(
    session: &mut Session,
    force: bool,
    method: &str,
    url: &str,
    body: &[u8],
) -> Result<Vec<u8>, u32> {
    let (authorization, signature) = authorize(session, force, method, url, body).await?;
    let mut out = Vec::new();
    put(&mut out, authorization.as_bytes());
    put(&mut out, signature.as_bytes());
    Ok(out)
}

const COLLECTIONS_URL: &str = "https://collections.mp.microsoft.com/v8.0/collections/b2bLicensePreview";
const MAX_COLLECTION_PAGES: usize = 20;
/// XStoreProductKind flags in GDK order, with their Collections entitlement filters.
const PRODUCT_KINDS: [(u32, &str); 5] = [
    (0x01, "*:Consumable"),
    (0x02, "*:Durable"),
    (0x04, "*:Game"),
    (0x08, "*:Pass"),
    (0x10, "*:UnmanagedConsumable"),
];

fn unix_time(value: Option<&serde_json::Value>) -> i64 {
    value
        .and_then(|v| v.as_str())
        .and_then(|v| chrono::DateTime::parse_from_rfc3339(v).ok())
        .map(|v| v.timestamp())
        .unwrap_or(0)
}

/// "[DD:]HH:MM:SS[.fraction]" (Collections trialTimeRemaining) in whole seconds.
fn trial_seconds(value: Option<&serde_json::Value>) -> u32 {
    let Some(text) = value.and_then(|v| v.as_str()) else {
        return 0;
    };
    let parts: Vec<&str> = text.split(':').collect();
    let number = |s: &str| s.split('.').next().and_then(|n| n.parse::<u64>().ok());
    let seconds = match parts.as_slice() {
        [d, h, m, s] => (|| Some(((number(d)? * 24 + number(h)?) * 60 + number(m)?) * 60 + number(s)?))(),
        [h, m, s] => (|| Some((number(h)? * 60 + number(m)?) * 60 + number(s)?))(),
        _ => None,
    };
    seconds.unwrap_or(0).min(u64::from(u32::MAX)) as u32
}

/// One item: str productId, str skuId, str productKind, str status,
/// i64 acquired/start/end (Unix seconds), u32 quantity, u32 isTrial,
/// u32 trial seconds remaining, str inAppOfferToken, str devOfferId.
fn encode_item(item: &serde_json::Value, out: &mut Vec<u8>) {
    let text = |key: &str| item.get(key).and_then(|v| v.as_str()).unwrap_or_default();
    let kind = item
        .get("productKind")
        .or_else(|| item.get("productType"))
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    put(out, text("productId").as_bytes());
    put(out, text("skuId").as_bytes());
    put(out, kind.as_bytes());
    put(out, text("status").as_bytes());
    for key in ["acquiredDate", "startDate", "endDate"] {
        out.extend_from_slice(&unix_time(item.get(key)).to_le_bytes());
    }
    let quantity = item.get("quantity").and_then(|v| v.as_u64()).unwrap_or(0);
    out.extend_from_slice(&(quantity.min(u64::from(u32::MAX)) as u32).to_le_bytes());
    let trial = item.get("trialData");
    let is_trial = trial.and_then(|t| t.get("isTrial")).and_then(|v| v.as_bool()).unwrap_or(false);
    out.extend_from_slice(&u32::from(is_trial).to_le_bytes());
    out.extend_from_slice(&trial_seconds(trial.and_then(|t| t.get("trialTimeRemaining"))).to_le_bytes());
    put(out, text("inAppOfferToken").as_bytes());
    put(out, text("devOfferId").as_bytes());
}

/// "a.b.c.d" (1 to 4 numeric parts) as a comparable tuple.
fn parse_version(text: &str) -> Option<[u32; 4]> {
    let mut out = [0u32; 4];
    let parts: Vec<&str> = text.split('.').collect();
    if parts.is_empty() || parts.len() > 4 {
        return None;
    }
    for (slot, part) in out.iter_mut().zip(&parts) {
        *slot = part.parse().ok()?;
    }
    Some(out)
}

/// Package service versions: "a.b.c.d.<version id>" (observed for
/// GetBasePackage), plain dotted, or a packed Windows package version
/// (major << 48 | minor << 32 | build << 16 | revision) as a decimal string.
fn parse_service_version(text: &str) -> Option<[u32; 4]> {
    if text.contains('.') {
        let parts: Vec<&str> = text.splitn(5, '.').collect();
        if parts.len() == 5 {
            // The fifth component is the package's version ID, not a number.
            return parse_version(&parts[..4].join("."));
        }
        return parse_version(text);
    }
    let packed: u64 = text.parse().ok()?;
    Some([(packed >> 48) as u32, (packed >> 32) as u32 & 0xffff, (packed >> 16) as u32 & 0xffff, packed as u32 & 0xffff])
}

/// XStoreQueryGameAndDlcPackageUpdates for the base game: the installed
/// version (MicrosoftGame.Config) against the latest base package Microsoft's
/// update service lists for the title's Windows.Desktop content ID.
/// Response: u32 state (0 up to date, 1 newer version available, 2 installed
/// is newer than listed), str latest version, str content ID.
async fn package_update(
    context: &SimpleContext,
    session: &mut Session,
    store_id: &str,
    installed: &str,
) -> Result<Vec<u8>, u32> {
    let url = format!(
        "https://displaycatalog.mp.microsoft.com/v7.0/products/{store_id}?market=neutral&languages=en,neutral"
    );
    let response = context.client.get(url).send().await.map_err(|err| {
        tracing::warn!("Catalog request failed: {}", describe(err));
        AUTH_FAILED
    })?;
    if !response.status().is_success() {
        tracing::warn!("Catalog lookup returned HTTP {}", response.status());
        return Err(AUTH_FAILED);
    }
    let product: serde_json::Value = response.json().await.map_err(|_| AUTH_FAILED)?;
    let content_id = product["Product"]["DisplaySkuAvailabilities"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|a| a["Sku"]["Properties"]["Packages"].as_array().into_iter().flatten())
        .find(|p| {
            p["PlatformDependencies"]
                .as_array()
                .is_some_and(|d| d.iter().any(|d| d["PlatformName"].as_str() == Some("Windows.Desktop")))
        })
        .and_then(|p| p["ContentId"].as_str())
        .map(str::to_owned)
        .ok_or_else(|| {
            tracing::warn!("No Windows.Desktop package with a content ID in the catalog");
            AUTH_FAILED
        })?;
    let url = format!("{}/GetBasePackage/{content_id}", xodus::XBOX_LIVE_PACKAGES_PC);
    let (authorization, signature) = authorize(session, false, "GET", &url, b"").await?;
    let mut request = context
        .client
        .get(&url)
        .header("x-xbl-contract-version", "3")
        .header("Authorization", authorization);
    if !signature.is_empty() {
        request = request.header("Signature", signature);
    }
    let response = request.send().await.map_err(|err| {
        tracing::warn!("Package service request failed: {}", describe(err));
        AUTH_FAILED
    })?;
    if !response.status().is_success() {
        tracing::warn!("Package service returned HTTP {}", response.status());
        return Err(AUTH_FAILED);
    }
    let package: serde_json::Value = response.json().await.map_err(|_| AUTH_FAILED)?;
    if package["PackageFound"].as_bool() != Some(true) {
        tracing::warn!("Package service did not find the base package");
        return Err(AUTH_FAILED);
    }
    let version = &package["Version"];
    let newest = match version {
        serde_json::Value::String(text) => parse_service_version(text),
        serde_json::Value::Number(number) => number.as_u64().and_then(|n| parse_service_version(&n.to_string())),
        _ => None,
    };
    let (Some(have), Some(newest)) = (parse_version(installed), newest) else {
        let shown: String = version.to_string().chars().take(40).collect();
        tracing::warn!("Package service version is not numeric: {shown}");
        return Err(AUTH_FAILED);
    };
    let latest = format!("{}.{}.{}.{}", newest[0], newest[1], newest[2], newest[3]);
    let state: u32 = match have.cmp(&newest) {
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Less => 1,
        std::cmp::Ordering::Greater => 2,
    };
    let mut out = state.to_le_bytes().to_vec();
    put(&mut out, latest.as_bytes());
    put(&mut out, content_id.as_bytes());
    Ok(out)
}

/// XStoreQueryLicenseToken: a signed license token from Microsoft's licensing
/// service for the title (parent) and the requested products, with the
/// title's developer string, issued for this account and device as Gaming
/// Services does (same exchange as `xodus-cli`'s content license).
async fn license_token(
    context: &SimpleContext,
    store_id: &str,
    products: &[&str],
    developer: &str,
) -> Result<String, u32> {
    use xodus::models::live::ExchangeUserTokenOutcome;
    use xodus::models::secrets::Token;
    use xodus::models::soap;
    const HOSTING_APP: &str = "{d6d5a677-0872-4ab0-9442-bb792fce85c5}";
    let fail = |what: &str| {
        tracing::warn!("License token unavailable: {what}");
        AUTH_FAILED
    };
    let tokens = context.tokens();
    let Ok(Token::Legacy(device)) = tokens.get_device_sts_token() else {
        return Err(fail("no device session"));
    };
    let Ok(Token::Legacy(user_sts)) = tokens.get_user_sts_token() else {
        return Err(fail("no user session"));
    };
    let user = tokens.get_user().map_err(|_| fail("no user record"))?;
    let device_ms = xodus::api::live::exchange_device_token(
        &context.client,
        device.clone(),
        HOSTING_APP.into(),
        "www.microsoft.com".into(),
        Some(soap::PolicyReference::mbi_ssl()),
    )
    .await
    .map_err(|_| fail("device token exchange failed"))?;
    let Token::Compact(device_ms) = device_ms.into() else {
        return Err(fail("unexpected device token"));
    };
    let user_ms = xodus::api::live::exchange_user_token(
        &context.client,
        user_sts,
        user.username,
        device,
        None,
        Some("Silent".into()),
        HOSTING_APP.into(),
        &[("www.microsoft.com".into(), Some(soap::PolicyReference::mbi_ssl()))],
    )
    .await
    .map_err(|_| fail("user token exchange failed"))?;
    let user_ms: Token = match user_ms {
        ExchangeUserTokenOutcome::Issued(soap::BodyContent::RequestSecurityTokenResponseCollection(mut c))
            if !c.security_tokens.is_empty() => c.security_tokens.remove(0).into(),
        ExchangeUserTokenOutcome::Issued(soap::BodyContent::RequestSecurityTokenResponse(t)) => (*t).into(),
        _ => return Err(fail("user token not issued")),
    };
    let Token::Compact(user_ms) = user_ms else {
        return Err(fail("unexpected user token"));
    };
    let token = xodus::licensing::content::get_license_token(
        &context.client,
        device_ms,
        user_ms,
        user.puid,
        store_id.to_owned(),
        products.iter().map(|p| p.to_string()).collect(),
        developer.to_owned(),
    )
    .await
    .map_err(|err| {
        tracing::warn!("License token request failed: {}", describe(err));
        AUTH_FAILED
    })?;
    if token.is_empty() {
        return Err(fail("empty token"));
    }
    Ok(token)
}

/// Public Microsoft Store catalog entries (no account), in batches.
async fn catalog(context: &SimpleContext, ids: &[String]) -> Result<Vec<serde_json::Value>, u32> {
    let mut products = Vec::new();
    for batch in ids.chunks(CATALOG_BATCH) {
        let url = format!(
            "https://displaycatalog.mp.microsoft.com/v7.0/products?bigIds={}&market=US&languages=en-US,neutral",
            batch.join(",")
        );
        let response = context.client.get(url).send().await.map_err(|err| {
            tracing::warn!("Catalog request failed: {}", describe(err));
            AUTH_FAILED
        })?;
        if !response.status().is_success() {
            tracing::warn!("Catalog lookup returned HTTP {}", response.status());
            return Err(AUTH_FAILED);
        }
        let page: serde_json::Value = response.json().await.map_err(|err| {
            tracing::warn!("Catalog response unreadable: {}", describe(err));
            AUTH_FAILED
        })?;
        products.extend(page["Products"].as_array().cloned().unwrap_or_default());
    }
    Ok(products)
}

/// Whether a catalog product is the title itself or names it as its parent.
fn belongs_to(product: &serde_json::Value, store_id: &str) -> bool {
    product["ProductId"].as_str() == Some(store_id)
        || product["MarketProperties"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|m| m["RelatedProducts"].as_array().into_iter().flatten())
            .any(|r| r["RelationshipType"].as_str() == Some("Parent") && r["RelatedProductId"].as_str() == Some(store_id))
}

/// Entitled products of this title. Each product: str storeId, str title,
/// str description, str language, str productKind, u32 has digital download
/// (catalog packages), u32 sku count, then per
/// SKU: str skuId, str title, and the encode_item fields of its entitlement.
/// Prices are not reported for owned products.
async fn entitled_products(
    context: &SimpleContext,
    store_id: &str,
    items: &[serde_json::Value],
) -> Result<Vec<u8>, u32> {
    let mut ids: Vec<String> = items
        .iter()
        .filter_map(|i| i["productId"].as_str().map(str::to_owned))
        .collect();
    ids.sort();
    ids.dedup();
    let catalog = catalog(context, &ids).await?;
    let mut out = Vec::new();
    let mut count = 0u32;
    for product in catalog.iter().filter(|p| belongs_to(p, store_id)) {
        let id = product["ProductId"].as_str().unwrap_or_default();
        let owned: Vec<&serde_json::Value> = items.iter().filter(|i| i["productId"].as_str() == Some(id)).collect();
        if owned.is_empty() {
            continue;
        }
        let text = |value: &serde_json::Value| value.as_str().unwrap_or_default().as_bytes().to_vec();
        let local = &product["LocalizedProperties"][0];
        put(&mut out, id.as_bytes());
        put(&mut out, &text(&local["ProductTitle"]));
        put(&mut out, &text(&local["ShortDescription"]));
        put(&mut out, &text(&local["Language"]));
        put(&mut out, &text(&product["ProductKind"]));
        let downloads = product["DisplaySkuAvailabilities"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|a| a["Sku"]["Properties"]["Packages"].as_array().is_some_and(|p| !p.is_empty()));
        out.extend_from_slice(&u32::from(downloads).to_le_bytes());
        out.extend_from_slice(&(owned.len() as u32).to_le_bytes());
        for item in owned {
            let sku = item["skuId"].as_str().unwrap_or_default();
            let sku_title = product["DisplaySkuAvailabilities"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|a| a["Sku"]["SkuId"].as_str() == Some(sku))
                .and_then(|a| a["Sku"]["LocalizedProperties"][0]["SkuTitle"].as_str())
                .unwrap_or_default();
            put(&mut out, sku.as_bytes());
            put(&mut out, sku_title.as_bytes());
            encode_item(item, &mut out);
        }
        count += 1;
    }
    let mut reply = count.to_le_bytes().to_vec();
    reply.extend_from_slice(&out);
    Ok(reply)
}

/// The user's Microsoft Store entitlements through Collections v8 with the
/// title's delegated XSTS token and request signature (Microsoft's documented
/// X-token authentication; the user comes from the token).
async fn collection_items(
    context: &SimpleContext,
    session: &mut Session,
    products: &[&str],
    kinds: u32,
    valid_only: bool,
) -> Result<Vec<serde_json::Value>, u32> {
    let filters: Vec<&str> = PRODUCT_KINDS
        .iter()
        .filter(|(flag, _)| kinds & flag != 0)
        .map(|(_, filter)| *filter)
        .collect();
    let mut request = serde_json::json!({
        "market": "neutral",
        "maxPageSize": 100,
        "excludeDuplicates": true,
        "expandSatisfyingItems": true,
        "validityType": if valid_only { "Valid" } else { "All" },
        "entitlementFilters": filters,
    });
    if !products.is_empty() {
        request["productSkuIds"] = products
            .iter()
            .map(|id| serde_json::json!({ "productId": id }))
            .collect();
    }
    let mut items = Vec::new();
    for _ in 0..MAX_COLLECTION_PAGES {
        let body = serde_json::to_vec(&request).map_err(|_| INVALID_ARG)?;
        let (authorization, signature) = authorize(session, false, "POST", COLLECTIONS_URL, &body).await?;
        let response = context
            .client
            .post(COLLECTIONS_URL)
            .header("Authorization", authorization)
            .header("Signature", signature)
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|err| {
                tracing::warn!("Collections request failed: {}", describe(err));
                AUTH_FAILED
            })?;
        let status = response.status();
        if !status.is_success() {
            tracing::warn!("Collections query returned HTTP {status}");
            return Err(AUTH_FAILED);
        }
        let page: serde_json::Value = response.json().await.map_err(|err| {
            tracing::warn!("Collections response unreadable: {}", describe(err));
            AUTH_FAILED
        })?;
        items.extend(page["items"].as_array().cloned().unwrap_or_default());
        match page["continuationToken"].as_str().filter(|t| !t.is_empty()) {
            Some(token) => request["continuationToken"] = token.into(),
            None => return Ok(items),
        }
    }
    tracing::warn!("Collections query exceeded {MAX_COLLECTION_PAGES} pages");
    Err(AUTH_FAILED)
}

static ENDPOINTS: LazyLock<
    tokio::sync::Mutex<Option<(xodus::xal::response::TitleEndpointsResponse, std::time::Instant)>>,
> = LazyLock::new(Default::default);

/// Microsoft's title endpoint list, refreshed hourly; needs no account.
async fn endpoints() -> Result<xodus::xal::response::TitleEndpointsResponse, u32> {
    let mut cache = ENDPOINTS.lock().await;
    if let Some((list, at)) = cache.as_ref()
        && at.elapsed() < std::time::Duration::from_secs(3600)
    {
        return Ok(list.clone());
    }
    let list = xodus::xal::get_endpoints().await.map_err(|err| {
        tracing::warn!("Title endpoint list unavailable: {}", describe(err));
        AUTH_FAILED
    })?;
    *cache = Some((list.clone(), std::time::Instant::now()));
    Ok(list)
}

/// Response: u32 WinHTTP protocol flags, u32 count, then per thumbprint u32
/// type (0 leaf, 1 issuer) and its SHA-1 bytes. Thumbprints are those Microsoft
/// lists for the best-matching endpoint (same host/path matching as xal);
/// URLs without pinned certificates get none.
fn security(list: &xodus::xal::response::TitleEndpointsResponse, url: &str) -> Result<Vec<u8>, u32> {
    let mut url = xodus::xal::url::Url::parse(url).map_err(|_| INVALID_ARG)?;
    match url.scheme() {
        "wss" => drop(url.set_scheme("https")),
        "ws" => drop(url.set_scheme("http")),
        "http" | "https" => {}
        _ => return Err(INVALID_ARG),
    }
    let host = url.host_str().ok_or(INVALID_ARG)?.to_ascii_lowercase();
    let matched = list
        .end_points
        .iter()
        .filter(|e| {
            e.protocol.eq_ignore_ascii_case(url.scheme())
                && match e.host_type.as_str() {
                    "fqdn" => host == e.host,
                    "wildcard" => host.ends_with(e.host.trim_start_matches('*')),
                    _ => false,
                }
                && e.path.as_ref().is_none_or(|path| url.path() == path)
        })
        .max_by_key(|e| e.host.len());
    let mut prints = Vec::new();
    for &index in matched.and_then(|e| e.server_cert_index.as_ref()).into_iter().flatten() {
        let cert = list.certs.get(index as usize).ok_or(AUTH_FAILED)?;
        let hex = cert.thumbprint.as_bytes();
        if hex.len() != 40 || prints.len() == MAX_THUMBPRINTS {
            return Err(AUTH_FAILED);
        }
        let bytes = hex
            .chunks(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
            .collect::<Option<Vec<u8>>>()
            .ok_or(AUTH_FAILED)?;
        prints.push((u32::from(cert.is_issuer.unwrap_or(false)), bytes));
    }
    let mut out = TLS_PROTOCOLS.to_le_bytes().to_vec();
    out.extend_from_slice(&(prints.len() as u32).to_le_bytes());
    for (kind, bytes) in prints {
        out.extend_from_slice(&kind.to_le_bytes());
        put(&mut out, &bytes);
    }
    Ok(out)
}

async fn process(payload: &[u8], context: &SimpleContext) -> Result<Vec<u8>, u32> {
    let (app, title, request) = parse(payload)?;
    if let Request::Security { url } = request {
        return security(&endpoints().await?, url);
    }
    if let Request::LicenseToken { store_id, products, developer } = request {
        let token = license_token(context, store_id, &products, developer).await?;
        let mut out = Vec::new();
        put(&mut out, token.as_bytes());
        return Ok(out);
    }
    let force = matches!(request, Request::Token { force: true, .. });
    // One title sign-in at a time; concurrent requests reuse its result.
    let mut sessions = SESSIONS.lock().await;
    let key = (app, title);
    if force || !sessions.get(&key).is_some_and(Session::valid) {
        sessions.remove(&key);
        let session = sign_in(context, &key.0, title).await?;
        sessions.insert(key.clone(), session);
    }
    let session = sessions.get_mut(&key).ok_or(AUTH_FAILED)?;
    match request {
        Request::Profile => profile(session),
        Request::Security { .. } | Request::LicenseToken { .. } => Err(INVALID_ARG),
        Request::PackageUpdate { store_id, installed } => package_update(context, session, store_id, installed).await,
        Request::Collections {
            products,
            kinds,
            valid_only,
        } => {
            let items = collection_items(context, session, &products, kinds, valid_only).await?;
            let mut out = (items.len() as u32).to_le_bytes().to_vec();
            for item in &items {
                encode_item(item, &mut out);
            }
            Ok(out)
        }
        Request::EntitledProducts { store_id, kinds } => {
            let items = collection_items(context, session, &[], kinds, true).await?;
            entitled_products(context, store_id, &items).await
        }
        Request::Token {
            force,
            method,
            url,
            body,
        } => token(session, force, method, url, body).await,
    }
}

/// Frame: u32 length + payload. Reply: u32 magic, u32 version, u32 HRESULT,
/// u32 length + payload (empty on failure).
pub async fn handle(
    socket: &mut tokio::net::UnixStream,
    context: &SimpleContext,
) -> std::io::Result<()> {
    let length = socket.read_u32_le().await? as usize;
    if length > MAX_REQUEST {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    let mut payload = vec![0; length];
    socket.read_exact(&mut payload).await?;
    let mut extra = [0u8; 1];
    // EOF or cancellation drops the operation, as for the identity requests.
    let result = tokio::select! {
        result = tokio::time::timeout(std::time::Duration::from_secs(60), process(&payload, context)) =>
            result.unwrap_or(Err(TIMEOUT)),
        _ = socket.read(&mut extra) => return Ok(()),
    };
    tracing::debug!(
        hr = result.as_ref().err().copied().unwrap_or(0),
        "Title request completed"
    );
    let (hr, body) = match result {
        Ok(body) => (0, body),
        Err(hr) => (hr, Vec::new()),
    };
    let mut out = Vec::with_capacity(16 + body.len());
    out.extend_from_slice(&super::user::MAGIC.to_le_bytes());
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&hr.to_le_bytes());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    socket.write_all(&out).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(op: u32, app: &str, title: u32, tail: &[u8]) -> Vec<u8> {
        let mut out = op.to_le_bytes().to_vec();
        put(&mut out, app.as_bytes());
        out.extend_from_slice(&title.to_le_bytes());
        out.extend_from_slice(tail);
        out
    }

    fn nsal_fixture() -> xodus::xal::response::TitleEndpointsResponse {
        serde_json::from_value(serde_json::json!({"EndPoints": [
            {"Protocol":"https","Host":"*.sunrise.msgamestudios.com","HostType":"wildcard","RelyingParty":"rp://msfsservices.msgamestudios.com/","TokenType":"JWT"},
            {"Protocol":"https","Host":"*.kittyhawk2.msgamestudios.com","HostType":"wildcard","RelyingParty":"rp://msfsservices.msgamestudios.com/","TokenType":"JWT"},
            {"Protocol":"https","Host":"*.playfabapi.com","HostType":"wildcard","RelyingParty":"rp://msfsplayfabapi.com/","TokenType":"JWT"},
            {"Protocol":"https","Host":"*.prod.catalog.playfab.com","HostType":"wildcard","RelyingParty":"rp://msfsplayfabapi.com/","TokenType":"JWT"},
            {"Protocol":"https","Host":"*","HostType":"wildcard"},
            {"Protocol":"http","Host":"*","HostType":"wildcard"}
        ]})).unwrap()
    }

    fn default_nsal_fixture() -> xodus::xal::response::TitleEndpointsResponse {
        serde_json::from_value(serde_json::json!({"EndPoints": [
            {"Protocol":"https","Host":"*.xboxlive.com","HostType":"wildcard","RelyingParty":"http://xboxlive.com","SignaturePolicyIndex":0},
            {"Protocol":"https","Host":"playfabapi.com","HostType":"fqdn","RelyingParty":"http://playfab.xboxlive.com/","SignaturePolicyIndex":0},
            {"Protocol":"https","Host":"*.playfabapi.com","HostType":"wildcard","RelyingParty":"http://playfab.xboxlive.com/","SignaturePolicyIndex":0}
        ], "SignaturePolicies":[{"Version":1,"SupportedAlgorithms":["ES256"],"MaxBodyBytes":8192}]})).unwrap()
    }

    #[test]
    fn title_nsal_selects_backend_and_preserves_default_authorization() {
        let title = nsal_fixture();
        let defaults = default_nsal_fixture();
        for (url, rp) in [
            ("https://xsts.kittyhawk2.msgamestudios.com/", "rp://msfsservices.msgamestudios.com/"),
            ("https://foo.sunrise.msgamestudios.com/", "rp://msfsservices.msgamestudios.com/"),
            ("https://C1771.playfabapi.com/", "rp://msfsplayfabapi.com/"),
            ("https://a.prod.catalog.playfab.com/", "rp://msfsplayfabapi.com/"),
        ] {
            let (actual, policy) = endpoint_authorization(Some(&title), &defaults, url).unwrap();
            assert_eq!(actual.as_deref(), Some(rp));
            assert!(policy.is_none(), "No inherited default signature for {url}");
        }
        for url in ["https://playfabapi.com/", "https://peoplehub.xboxlive.com/", "wss://rta.xboxlive.com/"] {
            assert_eq!(endpoint_authorization(Some(&title), &defaults, url).unwrap(),
                       endpoint_authorization(None, &defaults, url).unwrap());
            assert!(endpoint_authorization(Some(&title), &defaults, url).unwrap().1.is_some());
        }
        for url in ["https://kittyhawk2.msgamestudios.com/", "https://evilkittyhawk2.msgamestudios.com/",
                    "https://xsts.kittyhawk2.msgamestudios.com.evil/", "https://unrelated.example/",
                    "http://xsts.kittyhawk2.msgamestudios.com/"] {
            assert_eq!(endpoint_authorization(Some(&title), &defaults, url).unwrap(), (None, None));
        }
        assert_eq!(endpoint_authorization(Some(&title), &defaults, "file:///tmp/a").unwrap_err(), INVALID_ARG);
        assert_eq!(endpoint_authorization(Some(&title), &defaults, "invalid").unwrap_err(), INVALID_ARG);
    }

    #[test]
    fn title_nsal_matches_complete_default_fixture() {
        // Public Microsoft endpoint metadata already present in xodus' tests;
        // no account data, tokens, certificate bodies or live requests.
        let defaults: xodus::xal::response::TitleEndpointsResponse = serde_json::from_str(
            include_str!("../../tests/fixtures/default-endpoints.json")
        ).unwrap();
        let title = nsal_fixture();
        assert!(defaults.end_points.len() > 80);
        for (url, rp, signed) in [
            ("https://xsts.kittyhawk2.msgamestudios.com/", "rp://msfsservices.msgamestudios.com/", false),
            ("https://C1771.playfabapi.com/", "rp://msfsplayfabapi.com/", false),
            ("https://playfabapi.com/", "http://playfab.xboxlive.com/", false),
            ("https://title.mgt.xboxlive.com/titles/1615644955/endpoints", "http://xboxlive.com", true),
            ("https://peoplehub.xboxlive.com/", "http://xboxlive.com", true),
        ] {
            let (actual, policy) = endpoint_authorization(Some(&title), &defaults, url).unwrap();
            assert_eq!(actual.as_deref(), Some(rp), "{url}");
            assert_eq!(policy.is_some(), signed, "{url}");
        }
    }

    #[test]
    fn title_nsal_policy_is_scoped_to_winning_list_and_path() {
        let defaults = default_nsal_fixture();
        let mut title = nsal_fixture();
        title.end_points[2].signature_policy_index = Some(0);
        assert_eq!(endpoint_authorization(Some(&title), &defaults, "https://C1771.playfabapi.com/").unwrap_err(), AUTH_FAILED);
        title.signature_policies = defaults.signature_policies.clone();
        title.signature_policies[0].max_body_bytes = 17;
        assert_eq!(endpoint_authorization(Some(&title), &defaults, "https://C1771.playfabapi.com/").unwrap().1.unwrap().max_body_bytes, 17);
        title.end_points[2].signature_policy_index = Some(-1);
        assert_eq!(endpoint_authorization(Some(&title), &defaults, "https://C1771.playfabapi.com/").unwrap_err(), AUTH_FAILED);
        title.end_points[2].signature_policy_index = None;
        title.end_points[2].path = Some("/only".into());
        assert_eq!(endpoint_authorization(Some(&title), &defaults, "https://C1771.playfabapi.com/").unwrap(),
                   endpoint_authorization(None, &defaults, "https://C1771.playfabapi.com/").unwrap());
        assert!(endpoint_authorization(Some(&title), &defaults, "https://C1771.playfabapi.com/only").unwrap().1.is_none());
    }

    #[test]
    fn title_nsal_decode_rejects_failed_empty_malformed_and_oversized_responses() {
        // In-memory HTTP responses; no network, keychain, account or game.
        for (status, body) in [(401, "{}".to_owned()), (200, "SENTINEL_PRIVATE_BODY".to_owned()),
            (200, "{\"EndPoints\":[]}".to_owned()), (200, " ".repeat((1 << 20) + 1))] {
            assert_eq!(parse_title_endpoints(reqwest::StatusCode::from_u16(status).unwrap(), body.as_bytes()).unwrap_err(), AUTH_FAILED);
        }
        let body = serde_json::to_string(&nsal_fixture()).unwrap();
        assert_eq!(parse_title_endpoints(reqwest::StatusCode::OK, body.as_bytes()).unwrap(), nsal_fixture());
    }

    #[test]
    fn parse_validates_framing() {
        let app = "23cf167f-8716-4d4c-8dc1-20611e03a087";
        assert!(matches!(
            parse(&request(OP_PROFILE, app, 0x604cc91b, &[])),
            Ok((_, 0x604cc91b, Request::Profile))
        ));
        let mut tail = FORCE_REFRESH.to_le_bytes().to_vec();
        put(&mut tail, b"POST");
        put(&mut tail, b"https://example.xboxlive.com/path?q=1");
        put(&mut tail, b"{}");
        match parse(&request(OP_TOKEN, app, 1, &tail)) {
            Ok((_, 1, Request::Token { force, method, url, body })) => {
                assert!(force);
                assert_eq!(method, "POST");
                assert_eq!(url, "https://example.xboxlive.com/path?q=1");
                assert_eq!(body, b"{}");
            }
            _ => panic!("token request rejected"),
        }
        assert_eq!(parse(&request(OP_PROFILE, app, 0, &[])).err(), Some(INVALID_ARG));
        assert_eq!(parse(&request(OP_PROFILE, "", 1, &[])).err(), Some(INVALID_ARG));
        assert_eq!(parse(&request(OP_PROFILE, "a/b", 1, &[])).err(), Some(INVALID_ARG));
        assert_eq!(parse(&request(9, app, 1, &[])).err(), Some(INVALID_ARG));
        let mut url = Vec::new();
        put(&mut url, b"https://a.xboxlive.com/");
        assert!(matches!(parse(&request(OP_SECURITY, app, 1, &url)), Ok((_, 1, Request::Security { url: "https://a.xboxlive.com/" }))));
        assert_eq!(parse(&request(OP_PROFILE, app, 1, &[0])).err(), Some(INVALID_ARG));
        assert_eq!(parse(&request(OP_TOKEN, app, 1, &tail[..tail.len() - 1])).err(), Some(INVALID_ARG));
        assert_eq!(parse(&[1, 0]).err(), Some(INVALID_ARG));
        let mut huge = OP_PROFILE.to_le_bytes().to_vec();
        huge.extend_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(parse(&huge).err(), Some(INVALID_ARG));
    }

    #[test]
    fn collection_items_encode_dates_trials_and_kinds() {
        assert_eq!(trial_seconds(Some(&"09:43:52.8580690".into())), 9 * 3600 + 43 * 60 + 52);
        assert_eq!(trial_seconds(Some(&"2:01:00:00".into())), 2 * 86400 + 3600);
        assert_eq!(trial_seconds(Some(&"bad".into())), 0);
        assert_eq!(trial_seconds(None), 0);
        let item = serde_json::json!({
            "productId": "9P38D19T7LRV", "skuId": "0010", "productKind": "Game", "status": "Active",
            "acquiredDate": "2024-11-19T10:00:00+00:00", "startDate": "2024-11-19T10:00:00+00:00",
            "endDate": "9999-12-31T23:59:59.9999999+00:00", "quantity": 1,
            "trialData": {"isTrial": false, "isInTrialPeriod": false}
        });
        let mut out = Vec::new();
        encode_item(&item, &mut out);
        let mut r = Reader(&out);
        assert_eq!(r.str().unwrap(), "9P38D19T7LRV");
        assert_eq!(r.str().unwrap(), "0010");
        assert_eq!(r.str().unwrap(), "Game");
        assert_eq!(r.str().unwrap(), "Active");
        let dates: Vec<i64> = (0..3).map(|_| i64::from_le_bytes(r.take(8).unwrap().try_into().unwrap())).collect();
        assert_eq!(dates[0], 1732010400);
        assert_eq!(dates[2], 253402300799);
        assert_eq!((r.u32().unwrap(), r.u32().unwrap(), r.u32().unwrap()), (1, 0, 0));
        assert_eq!((r.str().unwrap(), r.str().unwrap()), ("", ""));
        assert!(r.0.is_empty());
        let mut tail = 2u32.to_le_bytes().to_vec();
        put(&mut tail, b"9P38D19T7LRV");
        put(&mut tail, b"9ABC/0010");
        tail.extend_from_slice(&6u32.to_le_bytes());
        tail.extend_from_slice(&1u32.to_le_bytes());
        let mut payload = OP_COLLECTIONS.to_le_bytes().to_vec();
        put(&mut payload, b"app");
        payload.extend_from_slice(&1u32.to_le_bytes());
        payload.extend_from_slice(&tail);
        assert!(matches!(parse(&payload), Ok((_, 1, Request::Collections { kinds: 6, valid_only: true, .. }))));
        let mut lt = OP_LICENSE_TOKEN.to_le_bytes().to_vec();
        put(&mut lt, b"app");
        lt.extend_from_slice(&1u32.to_le_bytes());
        put(&mut lt, b"9P38D19T7LRV");
        lt.extend_from_slice(&1u32.to_le_bytes());
        put(&mut lt, b"9ADDON");
        put(&mut lt, b"nonce-123");
        assert!(matches!(parse(&lt), Ok((_, 1, Request::LicenseToken { store_id: "9P38D19T7LRV", developer: "nonce-123", .. }))));
        let mut bad = OP_COLLECTIONS.to_le_bytes().to_vec();
        put(&mut bad, b"app");
        bad.extend_from_slice(&1u32.to_le_bytes());
        bad.extend_from_slice(&1u32.to_le_bytes());
        put(&mut bad, b"../x");
        bad.extend_from_slice(&[0; 8]);
        assert_eq!(parse(&bad).err(), Some(INVALID_ARG));
    }

    #[test]
    fn versions_compare_numerically() {
        assert_eq!(parse_version("1.9.18.0"), Some([1, 9, 18, 0]));
        assert_eq!(parse_version("1.10"), Some([1, 10, 0, 0]));
        assert!(parse_version("1.10").unwrap() > parse_version("1.9.18.0").unwrap());
        assert_eq!(parse_version("1.x"), None);
        assert_eq!(parse_version("1.2.3.4.5"), None);
        assert_eq!(parse_version(""), None);
        let packed = (1u64 << 48) | (9 << 32) | (18 << 16);
        assert_eq!(parse_service_version(&packed.to_string()), Some([1, 9, 18, 0]));
        assert_eq!(parse_service_version("1.9.18.0"), Some([1, 9, 18, 0]));
        assert_eq!(parse_service_version("abc"), None);
        assert_eq!(parse_service_version("1.9.18.0.22ec76d9-4dd8-4a39-a1b6-000000000000"), Some([1, 9, 18, 0]));
        assert_eq!(parse_service_version("1.9.x.0.22ec76d9"), None);
    }

    #[test]
    fn catalog_relationship_selects_title_add_ons() {
        let game = serde_json::json!({"ProductId": "9P38D19T7LRV", "MarketProperties": [{"RelatedProducts": [{"RelatedProductId": "9BUNDLE", "RelationshipType": "Bundle"}]}]});
        let addon = serde_json::json!({"ProductId": "9ADDON", "MarketProperties": [{"RelatedProducts": [{"RelatedProductId": "9P38D19T7LRV", "RelationshipType": "Parent"}]}]});
        let other = serde_json::json!({"ProductId": "9OTHER", "MarketProperties": [{"RelatedProducts": [{"RelatedProductId": "9SOMETHING", "RelationshipType": "Parent"}, {"RelatedProductId": "9P38D19T7LRV", "RelationshipType": "Bundle"}]}]});
        assert!(belongs_to(&game, "9P38D19T7LRV"));
        assert!(belongs_to(&addon, "9P38D19T7LRV"));
        assert!(!belongs_to(&other, "9P38D19T7LRV"));
        assert!(!belongs_to(&serde_json::json!({}), "9P38D19T7LRV"));
    }

    #[test]
    fn security_reports_listed_thumbprints_only() {
        let list: xodus::xal::response::TitleEndpointsResponse = serde_json::from_value(serde_json::json!({
            "EndPoints": [
                {"Protocol": "https", "Host": "*.xboxlive.com", "HostType": "wildcard"},
                {"Protocol": "https", "Host": "settings.xboxlive.com", "HostType": "fqdn", "ServerCertIndex": [0, 1]},
                {"Protocol": "https", "Host": "pinned.example.net", "HostType": "fqdn", "Path": "/only", "ServerCertIndex": [1]}
            ],
            "Certs": [
                {"Thumbprint": "54D9D20239080C32316ED9FF980A48988F4ADF2D", "IsIssuer": true, "RootCertIndex": 0},
                {"Thumbprint": "D5A9ACDB80066D0E67FF65A939BBBC952F8ED171", "RootCertIndex": 0}
            ],
            "RootCerts": []
        }))
        .unwrap();
        let reply = security(&list, "https://settings.xboxlive.com/settings?x=1").unwrap();
        assert_eq!(&reply[..4], &TLS_PROTOCOLS.to_le_bytes());
        assert_eq!(&reply[4..8], &2u32.to_le_bytes());
        assert_eq!(&reply[8..12], &1u32.to_le_bytes());
        assert_eq!(&reply[12..16], &20u32.to_le_bytes());
        assert_eq!(&reply[16..18], &[0x54, 0xd9]);
        assert_eq!(&reply[36..40], &0u32.to_le_bytes());
        for url in ["https://userpresence.xboxlive.com/x", "https://example.com/", "https://pinned.example.net/other", "wss://rta.xboxlive.com/connect"] {
            assert_eq!(&security(&list, url).unwrap()[4..8], &0u32.to_le_bytes(), "{url}");
        }
        assert_eq!(&security(&list, "https://pinned.example.net/only").unwrap()[4..8], &1u32.to_le_bytes());
        assert_eq!(security(&list, "ftp://example.com/").err(), Some(INVALID_ARG));
        let mut bad = list.clone();
        bad.certs[0].thumbprint = "XYZ".into();
        assert_eq!(security(&bad, "https://settings.xboxlive.com/").err(), Some(AUTH_FAILED));
    }

    #[test]
    fn signature_matches_xal_format_and_verifies() {
        use base64ct::Encoding;
        use p256::ecdsa::signature::hazmat::PrehashVerifier;
        let signer = RequestSigner::new();
        let policy: xodus::xal::SigningPolicy = serde_json::from_value(serde_json::json!({
            "Version": 1, "SupportedAlgorithms": ["ES256"], "MaxBodyBytes": 8192
        }))
        .unwrap();
        let body = br#"{"x":1}"#;
        let value = sign(&signer, &policy, "post", "https://a.xboxlive.com/p?q=1", "XBL3.0 x=1;t", body).unwrap();
        let bytes = base64ct::Base64::decode_vec(&value).unwrap();
        assert_eq!(bytes.len(), 4 + 8 + 64);
        assert_eq!(&bytes[..4], &1i32.to_be_bytes());
        let prehash = RequestSigner::prehash_message_data(
            &bytes[..4], &bytes[4..12], "POST", "/p?q=1", "XBL3.0 x=1;t", body, 8192,
        );
        let signature = p256::ecdsa::Signature::from_slice(&bytes[12..]).unwrap();
        let verifier = p256::ecdsa::VerifyingKey::from(signer.keypair.public_key());
        verifier.verify_prehash(&prehash, &signature).expect("signature does not verify");
        // FILETIME is within a minute of now.
        let filetime = u64::from_be_bytes(bytes[4..12].try_into().unwrap());
        let unix = (filetime / 10_000_000) as i64 - 11_644_473_600;
        assert!((unix - chrono::Utc::now().timestamp()).abs() < 60);
    }

    /// Prints only outcomes and claim names, never token or profile values.
    /// Fetches the title's own endpoint list (NSAL) the way Windows does, with
    /// the title's XSTS authorization and signature, and prints only host,
    /// relying party and token type of non-default entries. No token is printed.
    #[ignore = "requires authenticated desktop keychain and Xbox network access"]
    #[tokio::test]
    async fn live_title_endpoints() {
        use std::sync::Arc;
        use xodus::models::secrets::Token;
        xodus::secrets::init_secrets().expect("keychain initialization failed");
        let tokens = Arc::new(xodus::tokens::TokenManager::with_keychain_and_memory());
        let Ok(Token::Legacy(device)) = tokens.get_device_sts_token() else {
            panic!("existing device session unavailable");
        };
        let context = SimpleContext::new(device, tokens);
        let app = "23cf167f-8716-4d4c-8dc1-20611e03a087";
        let title = 0x604cc91b_u32;
        process(&request(OP_PROFILE, app, title, &[]), &context).await.expect("title sign-in failed");
        let defaults = endpoints().await.expect("default endpoint list");
        let default_hosts: std::collections::HashSet<String> = defaults.end_points.iter().map(|e| e.host.clone()).collect();
        let mut sessions = SESSIONS.lock().await;
        let session = sessions.get_mut(&(app.to_owned(), title)).expect("session");
        for url in [format!("https://title.mgt.xboxlive.com/titles/{title}/endpoints"),
                    "https://title.mgt.xboxlive.com/titles/current/endpoints".to_owned()] {
            let (authorization, signature) = match authorize(session, false, "GET", &url, b"").await {
                Ok(pair) => pair,
                Err(hr) => { println!("{url}: authorize failed {hr:#x}"); continue; }
            };
            println!("{url}: authorization present {}, signature present {}", !authorization.is_empty(), !signature.is_empty());
            let mut req = context.client.get(&url).header("x-xbl-contract-version", "1").header("Authorization", authorization);
            if !signature.is_empty() { req = req.header("Signature", signature); }
            let response = req.send().await.expect("request");
            let status = response.status();
            let body: serde_json::Value = response.json().await.unwrap_or_default();
            let list = body["EndPoints"].as_array().cloned().unwrap_or_default();
            println!("  HTTP {status}, {} endpoints", list.len());
            for e in &list {
                let host = e["Host"].as_str().unwrap_or("");
                if !default_hosts.contains(host) || host.contains("kittyhawk") || host.contains("msgamestudios") || host.contains("playfab") {
                    println!("  host {host} path {} rp {} token {} sigpolicy {}", e["Path"].as_str().unwrap_or("-"),
                             e["RelyingParty"].as_str().unwrap_or("-"), e["TokenType"].as_str().unwrap_or("-"), e["SignaturePolicyIndex"]);
                }
            }
        }
    }

    #[ignore = "requires authenticated desktop keychain and Xbox network access"]
    #[tokio::test]
    async fn live_title_profile_and_token() {
        use std::sync::Arc;
        use xodus::models::secrets::Token;
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new("xodus_service=warn"))
            .try_init();
        xodus::secrets::init_secrets().expect("keychain initialization failed");
        let tokens = Arc::new(xodus::tokens::TokenManager::with_keychain_and_memory());
        let Ok(Token::Legacy(device)) = tokens.get_device_sts_token() else {
            panic!("existing device session unavailable");
        };
        let context = SimpleContext::new(device, tokens);
        let app = std::env::var("XODUS_TEST_MSA_APP_ID")
            .unwrap_or_else(|_| "23cf167f-8716-4d4c-8dc1-20611e03a087".into());
        let title = std::env::var("XODUS_TEST_TITLE_ID")
            .ok()
            .and_then(|t| u32::from_str_radix(&t, 16).ok())
            .unwrap_or(0x604cc91b);
        let profile_reply = process(&request(OP_PROFILE, &app, title, &[]), &context).await;
        let profile_reply = profile_reply.expect("title sign-in failed");
        let mut r = Reader(&profile_reply[8..]);
        let names = ["gtg", "mgt", "mgs", "umg", "prv"];
        let lengths: Vec<_> = names.iter().map(|_| r.bytes().unwrap().len()).collect();
        println!("profile: xuid present, claim lengths {names:?} = {lengths:?}");
        for (label, products, kinds) in [("title product", vec!["9P38D19T7LRV"], 0x1f_u32), ("all durables", vec![], 0x02)] {
            let mut tail = (products.len() as u32).to_le_bytes().to_vec();
            for id in &products {
                put(&mut tail, id.as_bytes());
            }
            tail.extend_from_slice(&kinds.to_le_bytes());
            tail.extend_from_slice(&1u32.to_le_bytes());
            match process(&request(OP_COLLECTIONS, &app, title, &tail), &context).await {
                Ok(reply) => {
                    let mut r = Reader(&reply);
                    let count = r.u32().unwrap();
                    let mut kinds = std::collections::BTreeMap::new();
                    let mut title_items = Vec::new();
                    for _ in 0..count {
                        let product = r.str().unwrap().to_owned();
                        let sku = r.str().unwrap().to_owned();
                        let kind = r.str().unwrap().to_owned();
                        let status = r.str().unwrap().to_owned();
                        r.take(24 + 12).unwrap();
                        r.str().unwrap();
                        r.str().unwrap();
                        *kinds.entry(format!("{kind}/{status}")).or_insert(0) += 1;
                        if product == "9P38D19T7LRV" {
                            title_items.push(format!("{product}/{sku} {kind} {status}"));
                        }
                    }
                    println!("collections {label}: {count} items, kinds {kinds:?}, title items {title_items:?}");
                }
                Err(hr) => println!("collections {label}: failed {hr:#x}"),
            }
        }
        {
            let mut tail = Vec::new();
            put(&mut tail, b"9P38D19T7LRV");
            tail.extend_from_slice(&0x1f_u32.to_le_bytes());
            match process(&request(OP_ENTITLED_PRODUCTS, &app, title, &tail), &context).await {
                Ok(reply) => {
                    let mut r = Reader(&reply);
                    let count = r.u32().unwrap();
                    let mut summary = Vec::new();
                    for _ in 0..count {
                        r.str().unwrap();
                        let name = r.str().unwrap().to_owned();
                        r.str().unwrap();
                        r.str().unwrap();
                        let kind = r.str().unwrap().to_owned();
                        let downloads = r.u32().unwrap();
                        let skus = r.u32().unwrap();
                        for _ in 0..skus {
                            r.str().unwrap();
                            r.str().unwrap();
                            for _ in 0..4 { r.str().unwrap(); }
                            r.take(36).unwrap();
                            r.str().unwrap();
                            r.str().unwrap();
                        }
                        summary.push(format!("{kind}: {name} ({skus} sku, download {downloads})"));
                    }
                    println!("entitled products: {count} {summary:?}");
                }
                Err(hr) => println!("entitled products failed {hr:#x}"),
            }
        }
        {
            let mut tail = Vec::new();
            put(&mut tail, b"9P38D19T7LRV");
            tail.extend_from_slice(&1u32.to_le_bytes());
            put(&mut tail, b"9P38D19T7LRV");
            put(&mut tail, b"xodus-live-test");
            match process(&request(OP_LICENSE_TOKEN, &app, title, &tail), &context).await {
                Ok(reply) => println!("license token: length {}", Reader(&reply).str().unwrap().len()),
                Err(hr) => println!("license token failed {hr:#x}"),
            }
        }
        {
            let mut tail = Vec::new();
            put(&mut tail, b"9P38D19T7LRV");
            put(&mut tail, b"1.9.18.0");
            match process(&request(OP_PACKAGE_UPDATE, &app, title, &tail), &context).await {
                Ok(reply) => {
                    let mut r = Reader(&reply);
                    let state = r.u32().unwrap();
                    let latest = r.str().unwrap().to_owned();
                    let content = r.str().unwrap().len();
                    println!("package update: state {state} (0 current, 1 update, 2 newer), latest {latest}, content id length {content}");
                }
                Err(hr) => println!("package update failed {hr:#x}"),
            }
        }
        for url in ["https://settings.xboxlive.com/", "https://userpresence.xboxlive.com/"] {
            let mut tail = Vec::new();
            put(&mut tail, url.as_bytes());
            match process(&request(OP_SECURITY, &app, title, &tail), &context).await {
                Ok(reply) => println!("{url}: security flags {:#x}, thumbprints {}",
                    u32::from_le_bytes(reply[..4].try_into().unwrap()),
                    u32::from_le_bytes(reply[4..8].try_into().unwrap())),
                Err(hr) => println!("{url}: security failed {hr:#x}"),
            }
        }
        for url in [
            "https://userpresence.xboxlive.com/users/me",
            "https://titlehub.xboxlive.com/users/me/titles",
            "https://playfabapi.com/Client/LoginWithXbox",
            "https://example.com/",
        ] {
            let mut tail = 0u32.to_le_bytes().to_vec();
            put(&mut tail, b"GET");
            put(&mut tail, url.as_bytes());
            put(&mut tail, b"");
            let reply = match process(&request(OP_TOKEN, &app, title, &tail), &context).await {
                Ok(reply) => reply,
                Err(hr) => {
                    println!("{url}: failed {hr:#x}");
                    continue;
                }
            };
            let mut r = Reader(&reply);
            let token = r.str().unwrap();
            let signature = r.str().unwrap();
            println!(
                "{url}: token prefix ok {}, token length {}, signature length {}",
                token.starts_with("XBL3.0 x="),
                token.len(),
                signature.len()
            );
        }
    }
}
