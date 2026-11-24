//! What a Zode needs to talk to an off-net OIDC identity provider. The
//! Zode's own login ([crate::zode_login]) asks its AuthAgent for an
//! id_token from one of these providers.

use serde::{Deserialize, Serialize};

/// One OIDC identity provider, from the visa service's auth-services list.
/// Mirrors the visa service's `OidcClientConfig`. All public data.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct OidcIdpInfo {
    pub issuer: String,
    pub client_id: String,
    /// `None` for public clients (RFC 8252 s8.5); not a secret when present.
    pub client_secret: Option<String>,
    pub scopes: Vec<String>,
    pub allow_offline_access: bool,
}
