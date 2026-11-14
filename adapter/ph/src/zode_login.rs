//! A Zode's own login (zl-zipline#233): a person logs in on the Zode with
//! `ph-cli connect` or `ph-cli auth-agent`, and the Zode's own actor (the
//! machine, authenticated with RSA only) gains the user's OIDC attributes.
//! A logout drops them again while the machine stays connected.
//!
//! The login rides on the node's VS-API session, not on a link:
//!
//! - **Login** asks the visa service for a nonce (`getLoginNonce`), asks the
//!   registered [AuthAgentHandle] for an id_token bound to it, and sends
//!   `reauthorize` with the device leg plus that OIDC blob
//!   ([libnode::vsconn::VSConnHandle::reauthorize_own_actor]).
//! - **Logout** sends `reauthorize` with the device leg alone.
//! - **Silent renewal**: a timer task renews ahead of expiry with a
//!   non-interactive agent request. With no renewal by the expiry, ph logs
//!   the user out itself, so no stale user authority stays on the actor.
//! - **Session replaced**: every node authentication (a VS-API reconnect, a
//!   visa-service restart, a rejoin or a K2 re-authentication) makes the
//!   visa service build a new, device-only actor, so the login is gone.
//!   [session_replaced] records that and asks a resident agent for a new
//!   interactive login (gate g116 q2 = prompt).
//! - **Policy re-authentication** of the node's own address while logged in
//!   is answered with a renewal, which keeps the user, instead of the K2
//!   re-authentication, which would drop it ([answer_policy_reauth], q3).
//!
//! ph keeps no tokens: the refresh token stays in the agent process. ph
//! holds only the issuer, the login nonce and the expiry, and never logs an
//! id_token or a nonce.

use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use libnode::error::VSApiError;
use zpr::vsapi_types::{Connection, ErrorCode, OidcBlob};

use crate::actor_renewal::{renewal_attempt_timeout, renewal_deadline};
use crate::auth::OidcIdpInfo;
use crate::auth_agent::{AuthAgentHandle, AuthFailureReason, oidc_idps, request_id_token};
use crate::prelude::*;

/// How long to wait before the next silent-renewal attempt after one
/// failed. The wait never runs past the expiry, which logs the user out.
const RENEWAL_RETRY_INTERVAL: Duration = Duration::from_secs(10);

/// The least time between two silent renewals: refresh-grant tokens minted
/// in the same second can carry the same `iat`, and the visa service
/// requires it to increase.
const MIN_RENEWAL_SPACING: Duration = Duration::from_secs(1);

/// Where a Zode's own login stands.
#[derive(Clone, Debug)]
pub enum LoginState {
    /// Nobody is logged in. `last` is why the previous login attempt or
    /// login ended, if it did not end with a plain logout.
    LoggedOut { last: Option<AuthFailureReason> },
    /// A login is waiting for the user or the visa service.
    LoggingIn,
    /// A user is logged in.
    LoggedIn {
        /// The identity provider the user logged in with.
        idp: OidcIdpInfo,
        /// The visa-service nonce of the login. Silent renewals reuse it:
        /// the visa service ignores the nonce on a renewal, and a
        /// refresh-grant id_token carries no new one (OIDC Core §12.2).
        nonce: String,
        /// When the visa service granted the current authentication.
        granted_at: SystemTime,
        /// When the current authentication expires.
        expires: SystemTime,
    },
}

/// Why a login or logout request was refused or failed.
#[derive(Debug)]
pub enum LoginError {
    /// Someone is already logged in; log out first.
    AlreadyLoggedIn,
    /// Another login is still waiting for the user.
    InProgress,
    /// A logout was asked for, but nobody is logged in.
    NotLoggedIn,
    /// The login or logout failed.
    Failed(AuthFailureReason),
}

impl std::fmt::Display for LoginError {
    /// The text the admin RPC returns. A failure is the
    /// [AuthFailureReason] Debug spelling, which ph-cli maps onto its exit
    /// codes.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyLoggedIn => write!(f, "already logged in; run `ph-cli logout` first"),
            Self::InProgress => write!(f, "a login is already in progress"),
            Self::NotLoggedIn => write!(f, "not logged in"),
            Self::Failed(reason) => write!(f, "{reason:?}"),
        }
    }
}

/// The mutable part of [ZodeLogin], under one lock.
struct LoginData {
    state: LoginState,
    /// The agent the last login registered. It answers silent renewals and,
    /// while resident, the new login after a replaced session.
    agent: Option<AuthAgentHandle>,
    /// Bumped on every new login, so a renewal task of an earlier login
    /// knows it is stale.
    generation: u64,
    /// When the last `reauthorize` carrying the user's token (the login or
    /// a renewal) was submitted. Renewals coalesce and space themselves by
    /// it ([renew]).
    last_user_reauth: Option<SystemTime>,
}

/// A Zode's own login state, held on the [Assembly].
pub struct ZodeLogin {
    data: Mutex<LoginData>,
    /// Serializes every `reauthorize` of the node's own actor, so a renewal
    /// cannot put a user back after a logout went out.
    reauth_lock: tokio::sync::Mutex<()>,
    /// Held for a whole silent renewal, so overlapping renewals (the timer
    /// and policy requests) share one.
    renew_lock: tokio::sync::Mutex<()>,
    /// Bumped whenever a login ends or its expiry changes: a renewal
    /// waiting on an ended login's agent gives up instead of holding up the
    /// next login's renewals, and the renewal timer recomputes its deadline.
    changes: tokio::sync::watch::Sender<u64>,
}

impl Default for ZodeLogin {
    /// Logged out, with no agent and no recorded failure.
    fn default() -> Self {
        Self {
            data: Mutex::new(LoginData {
                state: LoginState::LoggedOut { last: None },
                agent: None,
                generation: 0,
                last_user_reauth: None,
            }),
            reauth_lock: tokio::sync::Mutex::new(()),
            renew_lock: tokio::sync::Mutex::new(()),
            changes: tokio::sync::watch::Sender::new(0),
        }
    }
}

impl ZodeLogin {
    /// The current state.
    pub fn state(&self) -> LoginState {
        self.data.lock().unwrap().state.clone()
    }

    /// Whether a user is logged in.
    #[cfg(test)]
    pub fn is_logged_in(&self) -> bool {
        matches!(self.data.lock().unwrap().state, LoginState::LoggedIn { .. })
    }

    /// When the current login expires, if logged in.
    #[cfg(test)]
    pub fn expires(&self) -> Option<SystemTime> {
        match self.data.lock().unwrap().state {
            LoginState::LoggedIn { expires, .. } => Some(expires),
            _ => None,
        }
    }

    /// Whether an agent is registered.
    #[cfg(test)]
    pub fn has_agent(&self) -> bool {
        self.data.lock().unwrap().agent.is_some()
    }

    /// Unregister `agent` if it is still the registered one (its admin
    /// connection closed, zipline#45). True if it was cleared. The login is
    /// kept until it expires (g116 q5 = keep).
    pub fn clear_agent_if(&self, agent: &AuthAgentHandle) -> bool {
        let mut data = self.data.lock().unwrap();
        if data.agent.as_ref().is_some_and(|a| a.same_channel(agent)) {
            data.agent = None;
            return true;
        }
        false
    }

    /// The `ph-cli login-status` text for the current state.
    pub fn status_text(&self) -> String {
        let data = self.data.lock().unwrap();
        format_status(&data.state, data.agent.is_some(), SystemTime::now())
    }

    /// Start a login with `agent`: refused while logging in or logged in.
    /// Otherwise registers the agent and moves to [LoginState::LoggingIn].
    fn begin_login(&self, agent: &AuthAgentHandle) -> Result<(), LoginError> {
        let mut data = self.data.lock().unwrap();
        match data.state {
            LoginState::LoggingIn => return Err(LoginError::InProgress),
            LoginState::LoggedIn { .. } => return Err(LoginError::AlreadyLoggedIn),
            LoginState::LoggedOut { .. } => {}
        }
        data.state = LoginState::LoggingIn;
        data.agent = Some(agent.clone());
        Ok(())
    }

    /// Record a successful login, whose `reauthorize` was submitted at
    /// `submitted`, and return its generation.
    fn logged_in(
        &self,
        idp: OidcIdpInfo,
        nonce: String,
        submitted: SystemTime,
        expires: SystemTime,
    ) -> u64 {
        let mut data = self.data.lock().unwrap();
        data.generation += 1;
        data.last_user_reauth = Some(submitted);
        let granted_at = SystemTime::now();
        data.state = LoginState::LoggedIn {
            idp,
            nonce,
            granted_at,
            expires,
        };
        data.generation
    }

    /// Move to logged out, recording `last`.
    fn logged_out(&self, last: Option<AuthFailureReason>) {
        self.data.lock().unwrap().state = LoginState::LoggedOut { last };
        self.changes.send_modify(|n| *n += 1);
    }

    /// The identity provider, nonce, grant time and expiry of the login of
    /// `generation`, if it is still the current login.
    fn current(&self, generation: u64) -> Option<(OidcIdpInfo, String, SystemTime, SystemTime)> {
        let data = self.data.lock().unwrap();
        match &data.state {
            LoginState::LoggedIn {
                idp,
                nonce,
                granted_at,
                expires,
            } if data.generation == generation => {
                Some((idp.clone(), nonce.clone(), *granted_at, *expires))
            }
            _ => None,
        }
    }

    /// The generation of the current login, if logged in.
    fn current_generation(&self) -> Option<u64> {
        let data = self.data.lock().unwrap();
        matches!(data.state, LoginState::LoggedIn { .. }).then_some(data.generation)
    }

    /// Record a renewal of the login of `generation`, submitted at
    /// `submitted`: a new grant time and expiry. Ignored if that login has
    /// ended meanwhile.
    fn renewed(&self, generation: u64, submitted: SystemTime, expires: SystemTime) {
        let mut data = self.data.lock().unwrap();
        if data.generation != generation {
            return;
        }
        data.last_user_reauth = Some(submitted);
        let granted_at = SystemTime::now();
        if let LoginState::LoggedIn {
            granted_at: g,
            expires: e,
            ..
        } = &mut data.state
        {
            *g = granted_at;
            *e = expires;
        }
        drop(data);
        self.changes.send_modify(|n| *n += 1);
    }

    /// If logged in, move to logged out with `reason` and return the
    /// registered agent (if any). `None` when nobody was logged in.
    fn drop_login(&self, reason: AuthFailureReason) -> Option<Option<AuthAgentHandle>> {
        let mut data = self.data.lock().unwrap();
        if !matches!(data.state, LoginState::LoggedIn { .. }) {
            return None;
        }
        data.state = LoginState::LoggedOut { last: Some(reason) };
        let agent = data.agent.clone();
        drop(data);
        self.changes.send_modify(|n| *n += 1);
        Some(agent)
    }

    /// When the last `reauthorize` carrying the user's token was submitted.
    fn last_user_reauth(&self) -> Option<SystemTime> {
        self.data.lock().unwrap().last_user_reauth
    }

    /// The registered agent, if any.
    fn agent(&self) -> Option<AuthAgentHandle> {
        self.data.lock().unwrap().agent.clone()
    }
}

/// The `ph-cli login-status` text for `state` at `now`: the state, the
/// issuer and time left when logged in, whether an agent is registered, and
/// the last failure when logged out. Never shows the nonce.
pub fn format_status(state: &LoginState, agent_registered: bool, now: SystemTime) -> String {
    let mut text = String::new();
    match state {
        LoginState::LoggedOut { .. } => text.push_str("State: logged out\n"),
        LoginState::LoggingIn => text.push_str("State: logging in\n"),
        LoginState::LoggedIn { idp, expires, .. } => {
            let left = expires.duration_since(now).unwrap_or(Duration::ZERO);
            text.push_str(&format!(
                "State: logged in\nIssuer: {}\nExpires in: {}s\n",
                idp.issuer,
                left.as_secs()
            ));
        }
    }
    text.push_str(if agent_registered {
        "Auth agent: registered\n"
    } else {
        "Auth agent: none\n"
    });
    if let LoginState::LoggedOut { last: Some(reason) } = state {
        text.push_str(&format!("Last failure: {reason:?}\n"));
    }
    text
}

/// The node's own actor address: the address `vs_worker` authenticates with.
fn actor_addr(asm: &Assembly) -> IpAddr {
    asm.get_local_dock_addr()
}

/// The VS-API handle, or [AuthFailureReason::AuthUnavailable] without one.
fn vsconn(asm: &Assembly) -> Result<&libnode::vsconn::VSConnHandle, AuthFailureReason> {
    asm.vsconn
        .as_ref()
        .ok_or(AuthFailureReason::AuthUnavailable)
}

/// Map a VS-API failure onto the reason ph-cli reports: `authError`,
/// `invalidSignature` and any other refusal are
/// [AuthFailureReason::VisaServiceRejected], `policyDenied` is
/// [AuthFailureReason::PolicyDenied], and a temporary condition (including
/// a transport failure) is [AuthFailureReason::AuthUnavailable].
fn vs_failure(err: VSApiError) -> AuthFailureReason {
    match err {
        VSApiError::CodedError(e) => match e.code {
            ErrorCode::PolicyDenied => AuthFailureReason::PolicyDenied,
            ErrorCode::TemporarilyUnavailable | ErrorCode::QuotaExceeded => {
                AuthFailureReason::AuthUnavailable
            }
            _ => AuthFailureReason::VisaServiceRejected(format!("{:?}: {}", e.code, e.message)),
        },
        _ => AuthFailureReason::AuthUnavailable,
    }
}

/// Whether `err` is the visa service's `temporarilyUnavailable`.
fn is_temporarily_unavailable(err: &VSApiError) -> bool {
    matches!(err, VSApiError::CodedError(e) if e.code == ErrorCode::TemporarilyUnavailable)
}

/// A `Connection.authExpires` (unix seconds) as a [SystemTime].
fn auth_expiry(conn: &Connection) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(conn.auth_expires)
}

/// Log in the Zode's own actor with `agent` (`ph-cli connect` and
/// `auth-agent`, and the new login after a replaced session). Refused while
/// another login is pending or someone is logged in. On success the
/// renewal timer is armed; on failure the reason is recorded for
/// `login-status`.
///
/// The attempt runs as its own task, so it always finishes and settles the
/// state even if the caller goes away (a cancelled admin RPC). It is
/// bounded anyway: an agent whose connection closed fails at once, and the
/// wait for the user is bounded.
pub async fn login(asm: &Arc<Assembly>, agent: AuthAgentHandle) -> Result<(), LoginError> {
    asm.zode_login.begin_login(&agent)?;
    let task_asm = asm.clone();
    tokio::task::spawn_local(async move { attempt_login(&task_asm, agent).await })
        .await
        .unwrap_or_else(|e| {
            Err(LoginError::Failed(AuthFailureReason::AgentError(format!(
                "the login task failed: {e}"
            ))))
        })
}

/// One login attempt after [ZodeLogin::begin_login]: obtain the login,
/// then record it and arm the renewal timer, or record the failure.
async fn attempt_login(asm: &Arc<Assembly>, agent: AuthAgentHandle) -> Result<(), LoginError> {
    match obtain_login(asm, &agent).await {
        Ok((idp, nonce, submitted, conn)) => {
            let expires = auth_expiry(&conn);
            info!(target: RPC, "Zode login: logged in with {}; expires in {}s",
                idp.issuer,
                expires.duration_since(SystemTime::now()).unwrap_or_default().as_secs());
            let generation = asm.zode_login.logged_in(idp, nonce, submitted, expires);
            spawn_renewal(asm, generation);
            Ok(())
        }
        Err(reason) => {
            warn!(target: RPC, "Zode login failed: {reason:?}");
            asm.zode_login.logged_out(Some(reason.clone()));
            Err(LoginError::Failed(reason))
        }
    }
}

/// The steps of a login: pick the identity provider, get a visa-service
/// nonce, ask the agent interactively for a token bound to it, and send
/// `[SS, OIDC]`. A `temporarilyUnavailable` answer is retried once with a
/// fresh nonce (the first one is spent). Returns the identity provider, the
/// nonce, when the `reauthorize` was submitted, and the visa service's
/// answer.
async fn obtain_login(
    asm: &Arc<Assembly>,
    agent: &AuthAgentHandle,
) -> Result<(OidcIdpInfo, String, SystemTime, Connection), AuthFailureReason> {
    // ponytail: the first advertised IdP; a choice of IdP waits for a
    // policy with more than one.
    let idp = oidc_idps(asm, "Zode login")
        .into_iter()
        .next()
        .ok_or(AuthFailureReason::AuthUnavailable)?;
    let vsconn = vsconn(asm)?;
    let mut retried = false;
    loop {
        let login_nonce = vsconn.get_login_nonce().await.map_err(vs_failure)?;
        // A token that arrives after the nonce expired would be refused.
        let left = login_nonce
            .expires_at
            .duration_since(SystemTime::now())
            .unwrap_or(Duration::ZERO);
        let wait = left.min(config::OIDC_USER_INTERACTION_TIMEOUT);
        let id_token =
            request_id_token(agent, idp.clone(), login_nonce.nonce.clone(), true, wait).await?;
        let blob = OidcBlob {
            issuer: idp.issuer.clone(),
            id_token,
            nonce: login_nonce.nonce.clone(),
        };
        let (submitted, result) = {
            let _serial = asm.zode_login.reauth_lock.lock().await;
            let submitted = SystemTime::now();
            let result = vsconn
                .reauthorize_own_actor(actor_addr(asm), Some(blob))
                .await;
            (submitted, result)
        };
        match result {
            Ok(conn) => return Ok((idp, login_nonce.nonce, submitted, conn)),
            Err(e) if is_temporarily_unavailable(&e) && !retried => {
                info!(target: RPC, "Zode login: the visa service is temporarily unavailable; retrying once with a new nonce");
                retried = true;
            }
            Err(e) => return Err(vs_failure(e)),
        }
    }
}

/// Log out the Zode's own actor: send the device leg alone, which drops the
/// user's attributes. An error when nobody is logged in. If the visa
/// service refuses, the user stays logged in and the reason is returned.
///
/// Like [login], the logout runs as its own task, so the state follows the
/// visa service even if the caller goes away once the request is queued.
pub async fn logout(asm: &Arc<Assembly>) -> Result<(), LoginError> {
    let generation = match asm.zode_login.state() {
        LoginState::LoggedIn { .. } => asm.zode_login.current_generation(),
        LoginState::LoggingIn => return Err(LoginError::InProgress),
        LoginState::LoggedOut { .. } => return Err(LoginError::NotLoggedIn),
    };
    let task_asm = asm.clone();
    tokio::task::spawn_local(async move {
        send_logout(&task_asm).await.map_err(LoginError::Failed)?;
        // A login that replaced this one meanwhile (after a session
        // change) is left alone.
        if generation
            .and_then(|g| task_asm.zode_login.current(g))
            .is_some()
        {
            task_asm.zode_login.logged_out(None);
        }
        info!(target: RPC, "Zode login: logged out");
        Ok(())
    })
    .await
    .unwrap_or_else(|e| {
        Err(LoginError::Failed(AuthFailureReason::AgentError(format!(
            "the logout task failed: {e}"
        ))))
    })
}

/// Send `reauthorize` with the device leg alone (a logout).
async fn send_logout(asm: &Arc<Assembly>) -> Result<(), AuthFailureReason> {
    let _serial = asm.zode_login.reauth_lock.lock().await;
    logout_locked(asm).await
}

/// [send_logout] for a caller that holds the `reauthorize` lock.
async fn logout_locked(asm: &Arc<Assembly>) -> Result<(), AuthFailureReason> {
    vsconn(asm)?
        .reauthorize_own_actor(actor_addr(asm), None)
        .await
        .map(|_| ())
        .map_err(vs_failure)
}

/// One silent renewal of the login of `generation`: a non-interactive agent
/// request with the login's nonce, then `[SS, OIDC]`. Success moves the
/// expiry forward. `Ok` without sending anything if that login has ended.
///
/// Overlapping renewals share one: a renewal returns `Ok` at once if the
/// login or another renewal was submitted after it was asked for. A
/// renewal is also spaced at least [MIN_RENEWAL_SPACING] from the last
/// login or renewal.
async fn renew(asm: &Arc<Assembly>, generation: u64) -> Result<(), AuthFailureReason> {
    let asked = SystemTime::now();
    let _renewing = asm.zode_login.renew_lock.lock().await;
    let last = asm.zode_login.last_user_reauth();
    if last.is_some_and(|submitted| submitted >= asked) {
        return Ok(());
    }
    if let Some(since) = last.and_then(|t| SystemTime::now().duration_since(t).ok()) {
        if since < MIN_RENEWAL_SPACING {
            tokio::time::sleep(MIN_RENEWAL_SPACING - since).await;
        }
    }
    let Some((idp, nonce, _, expires)) = asm.zode_login.current(generation) else {
        return Ok(());
    };
    let agent = asm.zode_login.agent().ok_or(AuthFailureReason::NoAgent)?;
    let vsconn = vsconn(asm)?;
    // Never past the expiry: the timer logs out then, and must not wait on
    // a silent agent to do so.
    let now = SystemTime::now();
    let timeout = renewal_attempt_timeout(now, expires)
        .min(expires.duration_since(now).unwrap_or(Duration::ZERO));
    // Give up if the login ends while its agent is asked: a stuck agent of
    // an ended login must not hold up the next login's renewals.
    let mut ended = asm.zode_login.changes.subscribe();
    let id_token = tokio::select! {
        reply = request_id_token(&agent, idp.clone(), nonce.clone(), false, timeout) => reply?,
        _ = ended.wait_for(|_| asm.zode_login.current(generation).is_none()) => return Ok(()),
    };
    let _serial = asm.zode_login.reauth_lock.lock().await;
    // A logout or a replaced session while the agent answered ends this
    // renewal: it must not put the user back.
    if asm.zode_login.current(generation).is_none() {
        return Ok(());
    }
    let blob = OidcBlob {
        issuer: idp.issuer,
        id_token,
        nonce,
    };
    let submitted = SystemTime::now();
    let conn = vsconn
        .reauthorize_own_actor(actor_addr(asm), Some(blob))
        .await
        .map_err(vs_failure)?;
    asm.zode_login
        .renewed(generation, submitted, auth_expiry(&conn));
    Ok(())
}

/// Arm the renewal timer of the login of `generation` on the local set.
fn spawn_renewal(asm: &Arc<Assembly>, generation: u64) {
    let asm = asm.clone();
    tokio::task::spawn_local(async move { renewal_loop(&asm, generation).await });
}

/// The renewal timer: sleep until renewal is due, renew silently, and
/// retry a failed renewal every [RENEWAL_RETRY_INTERVAL] until the expiry.
/// At the expiry with no renewal, log the user out
/// ([AuthFailureReason::LoginExpired]): otherwise a stale user authority
/// stays on the actor, and a later login would look like a renewal to the
/// visa service. Exits once the login of `generation` has ended.
async fn renewal_loop(asm: &Arc<Assembly>, generation: u64) {
    let lead = asm.config.get().auth_renewal_lead;
    // A policy renewal can move the expiry while this sleeps.
    let mut changes = asm.zode_login.changes.subscribe();
    let mut next_attempt: Option<SystemTime> = None;
    loop {
        let Some((_, _, granted_at, expires)) = asm.zode_login.current(generation) else {
            return;
        };
        let now = SystemTime::now();
        if now >= expires {
            match expire(asm, generation).await {
                Expiry::Ended => return,
                Expiry::Renewed => continue,
                // The logout was refused: the user may still be on the
                // actor, so stay logged in and retry.
                Expiry::Refused => {
                    tokio::time::sleep(RENEWAL_RETRY_INTERVAL).await;
                    continue;
                }
            }
        }
        let due = next_attempt.unwrap_or_else(|| renewal_deadline(granted_at, expires, lead));
        if now < due {
            let wake = due.min(expires);
            tokio::select! {
                () = tokio::time::sleep(wake.duration_since(now).unwrap_or_default()) => {}
                _ = changes.changed() => {}
            }
            continue;
        }
        match renew(asm, generation).await {
            Ok(()) => next_attempt = None,
            Err(reason) => {
                warn!(target: RPC, "Zode login: silent renewal failed: {reason:?}; retrying until the login expires");
                next_attempt = Some(SystemTime::now() + RENEWAL_RETRY_INTERVAL);
            }
        }
    }
}

/// What [expire] did.
enum Expiry {
    /// Logged out, or the login had ended anyway.
    Ended,
    /// A renewal landed meanwhile: the login is current again.
    Renewed,
    /// The visa service refused the logout.
    Refused,
}

/// The login of `generation` expired without a renewal: log out on the
/// visa service and record [AuthFailureReason::LoginExpired]. The expiry
/// is checked again under the `reauthorize` lock, so a renewal that landed
/// while this waited for it wins. If the visa service refuses the logout,
/// the state stays logged in, because the user may still be on the actor
/// (and a new login would look like a renewal), and the caller retries.
async fn expire(asm: &Arc<Assembly>, generation: u64) -> Expiry {
    let _serial = asm.zode_login.reauth_lock.lock().await;
    match asm.zode_login.current(generation) {
        None => return Expiry::Ended,
        Some((_, _, _, expires)) if expires > SystemTime::now() => return Expiry::Renewed,
        Some(_) => {}
    }
    warn!(target: RPC, "Zode login: expired without a renewal; logging out");
    if let Err(reason) = logout_locked(asm).await {
        warn!(target: RPC, "Zode login: the logout at expiry failed: {reason:?}; retrying");
        return Expiry::Refused;
    }
    asm.zode_login
        .logged_out(Some(AuthFailureReason::LoginExpired));
    Expiry::Ended
}

/// The node's VS-API session was replaced: call after every successful node
/// authentication (`vs_worker` and the K2 re-authentication). The visa
/// service built a new, device-only actor, so a login is gone. If someone
/// was logged in, record [AuthFailureReason::SessionReplaced] and, with an
/// agent still registered (a resident `auth-agent`), ask it for a new
/// interactive login with a new nonce (g116 q2 = prompt).
pub fn session_replaced(asm: &Arc<Assembly>) {
    let Some(agent) = asm
        .zode_login
        .drop_login(AuthFailureReason::SessionReplaced)
    else {
        return;
    };
    warn!(target: RPC, "Zode login: the visa service replaced this node's VS-API session, which dropped the login");
    let Some(agent) = agent else {
        info!(target: RPC, "Zode login: no auth agent is registered; run `ph-cli connect` or `ph-cli auth-agent` to log in again");
        return;
    };
    info!(target: RPC, "Zode login: asking the resident auth agent for a new login");
    let asm = asm.clone();
    tokio::task::spawn_local(async move {
        if let Err(e) = login(&asm, agent).await {
            warn!(target: RPC, "Zode login: the new login after the session change failed: {e}");
        }
    });
}

/// Answer a visa-service `requestAuthentication` for the node's own address
/// (a policy install, zipline#121) while a user is logged in (g116 q3): a
/// silent renewal re-runs authorization and keeps the user, where the K2
/// re-authentication would drop it. Only when no renewal can be had does it
/// fall back to K2 ([crate::vss_worker::spawn_self_reauth]), which replaces
/// the session ([session_replaced]). Returns false, doing nothing, when
/// nobody is logged in.
pub fn answer_policy_reauth(asm: &Arc<Assembly>) -> bool {
    use std::sync::atomic::Ordering;

    let Some(generation) = asm.zode_login.current_generation() else {
        return false;
    };
    let asm = asm.clone();
    tokio::task::spawn_local(async move {
        match renew(&asm, generation).await {
            Ok(()) => {
                info!(target: RPC, "Zode login: policy re-authentication answered with a renewal")
            }
            // The login ended while the renewal waited (a logout, maybe a
            // new login): K2 now would drop whoever is logged in now.
            Err(reason) if asm.zode_login.current(generation).is_none() => {
                info!(target: RPC, "Zode login: the policy renewal failed ({reason:?}) after its login ended; nothing to do");
            }
            Err(reason) => {
                warn!(target: RPC, "Zode login: no renewal for the policy re-authentication ({reason:?}); re-authenticating the node, which drops the login");
                if !asm.self_reauth_in_flight.swap(true, Ordering::SeqCst) {
                    crate::vss_worker::spawn_self_reauth(&asm);
                }
            }
        }
    });
    true
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::assembly::PhMode;
    use crate::assembly::test::{TestAssemblyBuilder, create_assembly};
    use crate::auth_agent::OidcCredentialRequest;
    use crate::fake_vs::{FakeVsState, connected_vsconn, eventually};
    use std::cell::RefCell;
    use std::rc::Rc;
    use tokio::task::LocalSet;
    use zpr::vsapi_types::{AuthBlob, ErrorCode, OidcClientConfig, ServiceDescriptor, ServiceT};

    /// The ZPR address of the Zode under test.
    pub(crate) const NODE_ADDR: &str = "fd5a:5052:3000::2";

    /// The issuer of the identity provider the visa service lists.
    const ISSUER: &str = "https://idp.test";

    /// The id_token every test agent answers with.
    pub(crate) const ID_TOKEN: &str = "FAKE.ID.TOKEN";

    /// The OIDC auth service the visa service lists for the Zode.
    fn idp_service() -> ServiceDescriptor {
        ServiceDescriptor {
            stype: ServiceT::OidcAuthentication,
            service_id: "idp".to_string(),
            service_uri: ISSUER.to_string(),
            zpr_addr: std::net::Ipv6Addr::UNSPECIFIED.into(),
            oidc: Some(OidcClientConfig {
                issuer: ISSUER.to_string(),
                client_id: "zode-client".to_string(),
                client_secret: None,
                scopes: vec!["openid".to_string()],
                allow_offline_access: true,
            }),
        }
    }

    /// A Zode at [NODE_ADDR] with a VS-API session to a fake visa service in
    /// `state`, which lists one OIDC identity provider when `with_idp`.
    pub(crate) async fn zode(
        state: FakeVsState,
        with_idp: bool,
    ) -> (Arc<Assembly>, Rc<RefCell<FakeVsState>>) {
        let addr: IpAddr = NODE_ADDR.parse().unwrap();
        let (fake, vs_handle) = connected_vsconn(state, addr).await;
        let asm = Arc::new(create_assembly(TestAssemblyBuilder {
            ph_mode: Some(PhMode::Node),
            vsconn: Some(Some(vs_handle)),
            config: Some(rcu::RcuBox::new(config::Config {
                zpr_addr: vec![addr],
                ..Default::default()
            })),
            ..TestAssemblyBuilder::new()
        }));
        if with_idp {
            asm.vs_auth_services
                .write()
                .unwrap()
                .update(None, vec![idp_service()]);
        }
        (asm, fake)
    }

    /// Every request a test agent saw: its nonce and whether it was
    /// interactive.
    type Seen = Rc<RefCell<Vec<(String, bool)>>>;

    /// A test agent that answers each request with `answer(interactive)`.
    /// `None` holds the request without answering, like a user who never
    /// finishes the login.
    fn agent(
        answer: impl Fn(bool) -> Option<Result<String, AuthFailureReason>> + 'static,
    ) -> (AuthAgentHandle, Seen) {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<OidcCredentialRequest>();
        let seen: Seen = Rc::default();
        let task_seen = seen.clone();
        tokio::task::spawn_local(async move {
            let mut held = Vec::new();
            while let Some(req) = rx.recv().await {
                task_seen
                    .borrow_mut()
                    .push((req.nonce.clone(), req.interactive));
                match answer(req.interactive) {
                    Some(reply) => {
                        let _ = req.reply.send(reply);
                    }
                    None => held.push(req),
                }
            }
        });
        (tx, seen)
    }

    /// An agent that always logs the user in.
    fn ok_agent() -> (AuthAgentHandle, Seen) {
        agent(|_| Some(Ok(ID_TOKEN.to_string())))
    }

    /// An agent that logs the user in interactively but has no refresh
    /// token, so it refuses every silent renewal.
    fn interactive_only_agent() -> (AuthAgentHandle, Seen) {
        agent(|interactive| {
            Some(if interactive {
                Ok(ID_TOKEN.to_string())
            } else {
                Err(AuthFailureReason::AgentError(
                    "no refresh token".to_string(),
                ))
            })
        })
    }

    /// The `reauthorize` requests the fake visa service saw, each as its
    /// blob shape: `None` for a device leg, `Some(nonce)` for an OIDC blob.
    fn reauth_shapes(fake: &Rc<RefCell<FakeVsState>>) -> Vec<Vec<Option<String>>> {
        fake.borrow()
            .reauths
            .iter()
            .map(|req| {
                assert_eq!(req.zpr_addr, NODE_ADDR.parse::<IpAddr>().unwrap());
                req.blobs
                    .iter()
                    .map(|blob| match blob {
                        AuthBlob::SS(ss) => {
                            assert_eq!(ss.cn, crate::fake_vs::NODE_CN);
                            None
                        }
                        AuthBlob::Oidc(oidc) => {
                            assert_eq!(oidc.issuer, ISSUER);
                            assert_eq!(oidc.id_token, ID_TOKEN);
                            Some(oidc.nonce.clone())
                        }
                        other => panic!("unexpected blob {other:?}"),
                    })
                    .collect()
            })
            .collect()
    }

    /// `[SS, OIDC{nonce}]`, a login or renewal, as [reauth_shapes] spells it.
    fn with_user(nonce: &str) -> Vec<Option<String>> {
        vec![None, Some(nonce.to_string())]
    }

    /// `[SS]`, a logout, as [reauth_shapes] spells it.
    fn device_only() -> Vec<Option<String>> {
        vec![None]
    }

    /// The login's last recorded failure, if logged out.
    fn last_failure(asm: &Assembly) -> Option<AuthFailureReason> {
        match asm.zode_login.state() {
            LoginState::LoggedOut { last } => last,
            other => panic!("expected logged out, got {other:?}"),
        }
    }

    /// A login asks the agent, interactively, for a token bound to the
    /// nonce the visa service minted, and sends `[SS, OIDC{that nonce}]`.
    #[tokio::test]
    async fn login_binds_the_token_to_the_visa_service_nonce() {
        LocalSet::new()
            .run_until(async {
                let (asm, fake) = zode(FakeVsState::default(), true).await;
                let (agent, seen) = ok_agent();

                login(&asm, agent).await.expect("login");

                assert_eq!(*seen.borrow(), vec![("vs-nonce-1".to_string(), true)]);
                assert_eq!(reauth_shapes(&fake), vec![with_user("vs-nonce-1")]);
                assert!(asm.zode_login.is_logged_in());
            })
            .await;
    }

    /// A second login while logged in is refused, and nothing is sent.
    #[tokio::test]
    async fn login_is_refused_while_logged_in() {
        LocalSet::new()
            .run_until(async {
                let (asm, fake) = zode(FakeVsState::default(), true).await;
                login(&asm, ok_agent().0).await.expect("first login");

                let err = login(&asm, ok_agent().0).await.unwrap_err();
                assert!(matches!(err, LoginError::AlreadyLoggedIn), "{err:?}");
                assert_eq!(fake.borrow().login_nonces, 1);
                assert_eq!(fake.borrow().reauths.len(), 1);
            })
            .await;
    }

    /// A login while another is still waiting for the user is refused.
    #[tokio::test]
    async fn login_is_refused_while_logging_in() {
        LocalSet::new()
            .run_until(async {
                let (asm, _fake) = zode(FakeVsState::default(), true).await;
                let (silent, _) = agent(|_| None);
                let first_asm = asm.clone();
                let _first =
                    tokio::task::spawn_local(async move { login(&first_asm, silent).await });
                assert!(
                    eventually(Duration::from_secs(5), || matches!(
                        asm.zode_login.state(),
                        LoginState::LoggingIn
                    ))
                    .await
                );

                let err = login(&asm, ok_agent().0).await.unwrap_err();
                assert!(matches!(err, LoginError::InProgress), "{err:?}");
            })
            .await;
    }

    /// With no identity provider listed, a login fails with
    /// `AuthUnavailable` before asking for a nonce.
    #[tokio::test]
    async fn login_without_an_idp_is_auth_unavailable() {
        LocalSet::new()
            .run_until(async {
                let (asm, fake) = zode(FakeVsState::default(), false).await;

                let err = login(&asm, ok_agent().0).await.unwrap_err();
                assert!(
                    matches!(err, LoginError::Failed(AuthFailureReason::AuthUnavailable)),
                    "{err:?}"
                );
                assert_eq!(fake.borrow().login_nonces, 0);
                assert_eq!(last_failure(&asm), Some(AuthFailureReason::AuthUnavailable));
            })
            .await;
    }

    /// A user who declines in the browser fails the login with
    /// `UserDeclined`, and nothing is sent to the visa service.
    #[tokio::test]
    async fn login_declined_by_the_user() {
        LocalSet::new()
            .run_until(async {
                let (asm, fake) = zode(FakeVsState::default(), true).await;
                let (declining, _) = agent(|_| Some(Err(AuthFailureReason::UserDeclined)));

                let err = login(&asm, declining).await.unwrap_err();
                assert!(
                    matches!(err, LoginError::Failed(AuthFailureReason::UserDeclined)),
                    "{err:?}"
                );
                assert!(fake.borrow().reauths.is_empty());
            })
            .await;
    }

    /// The visa service's refusals map onto the reasons ph-cli reports:
    /// `authError` and `invalidSignature` to `VisaServiceRejected`,
    /// `policyDenied` to `PolicyDenied`.
    #[tokio::test]
    async fn login_maps_visa_service_refusals() {
        for (code, expected) in [
            (ErrorCode::AuthError, "VisaServiceRejected"),
            (ErrorCode::InvalidSignature, "VisaServiceRejected"),
            (ErrorCode::PolicyDenied, "PolicyDenied"),
        ] {
            LocalSet::new()
                .run_until(async {
                    let (asm, _fake) = zode(
                        FakeVsState {
                            reauth_errors: [code.clone()].into(),
                            ..Default::default()
                        },
                        true,
                    )
                    .await;
                    let err = login(&asm, ok_agent().0).await.unwrap_err();
                    let LoginError::Failed(reason) = err else {
                        panic!("{code:?}: {err:?}");
                    };
                    let spelling: &'static str = (&reason).into();
                    assert_eq!(spelling, expected, "{code:?}");
                    assert!(!asm.zode_login.is_logged_in());
                })
                .await;
        }
    }

    /// `temporarilyUnavailable` is retried once, with a fresh nonce (the
    /// first was spent); a second one fails the login with
    /// `AuthUnavailable`.
    #[tokio::test]
    async fn login_retries_once_with_a_new_nonce_when_temporarily_unavailable() {
        LocalSet::new()
            .run_until(async {
                let (asm, fake) = zode(
                    FakeVsState {
                        reauth_errors: [ErrorCode::TemporarilyUnavailable].into(),
                        ..Default::default()
                    },
                    true,
                )
                .await;
                let (agent, seen) = ok_agent();
                login(&asm, agent).await.expect("the retry logs in");
                assert_eq!(
                    *seen.borrow(),
                    vec![
                        ("vs-nonce-1".to_string(), true),
                        ("vs-nonce-2".to_string(), true)
                    ]
                );
                assert_eq!(
                    reauth_shapes(&fake),
                    vec![with_user("vs-nonce-1"), with_user("vs-nonce-2")]
                );
            })
            .await;

        LocalSet::new()
            .run_until(async {
                let (asm, fake) = zode(
                    FakeVsState {
                        reauth_errors: [
                            ErrorCode::TemporarilyUnavailable,
                            ErrorCode::TemporarilyUnavailable,
                        ]
                        .into(),
                        ..Default::default()
                    },
                    true,
                )
                .await;
                let err = login(&asm, ok_agent().0).await.unwrap_err();
                assert!(
                    matches!(err, LoginError::Failed(AuthFailureReason::AuthUnavailable)),
                    "{err:?}"
                );
                assert_eq!(fake.borrow().reauths.len(), 2, "one retry, no more");
            })
            .await;
    }

    /// The wait for the user is bounded by the nonce's expiry: a token
    /// that arrives after it would be refused anyway.
    #[tokio::test]
    async fn login_wait_is_bounded_by_the_nonce_expiry() {
        LocalSet::new()
            .run_until(async {
                let (asm, _fake) = zode(
                    FakeVsState {
                        nonce_lifetime: Some(Duration::from_secs(2)),
                        ..Default::default()
                    },
                    true,
                )
                .await;
                let (silent, _) = agent(|_| None);
                let started = tokio::time::Instant::now();

                let err = login(&asm, silent).await.unwrap_err();
                assert!(
                    matches!(
                        err,
                        LoginError::Failed(AuthFailureReason::InteractionTimeout)
                    ),
                    "{err:?}"
                );
                assert!(started.elapsed() < Duration::from_secs(10));
            })
            .await;
    }

    /// A logout sends the device leg alone, which drops the user.
    #[tokio::test]
    async fn logout_sends_only_the_device_leg() {
        LocalSet::new()
            .run_until(async {
                let (asm, fake) = zode(FakeVsState::default(), true).await;
                login(&asm, ok_agent().0).await.expect("login");

                logout(&asm).await.expect("logout");

                assert_eq!(
                    reauth_shapes(&fake),
                    vec![with_user("vs-nonce-1"), device_only()]
                );
                assert_eq!(last_failure(&asm), None);
            })
            .await;
    }

    /// A logout while logged out is an error, and nothing is sent.
    #[tokio::test]
    async fn logout_while_logged_out_is_an_error() {
        LocalSet::new()
            .run_until(async {
                let (asm, fake) = zode(FakeVsState::default(), true).await;

                let err = logout(&asm).await.unwrap_err();
                assert!(matches!(err, LoginError::NotLoggedIn), "{err:?}");
                assert!(fake.borrow().reauths.is_empty());
            })
            .await;
    }

    /// When renewal comes due, the agent is asked silently for a token
    /// with the original nonce, `[SS, OIDC]` is sent, and the expiry moves
    /// forward.
    #[tokio::test]
    async fn renewal_is_silent_and_refreshes_the_expiry() {
        LocalSet::new()
            .run_until(async {
                let (asm, fake) = zode(
                    FakeVsState {
                        auth_lifetime: Some(Duration::from_secs(4)),
                        ..Default::default()
                    },
                    true,
                )
                .await;
                let (agent, seen) = ok_agent();
                login(&asm, agent).await.expect("login");
                let first_expiry = asm.zode_login.expires().unwrap();

                assert!(
                    eventually(Duration::from_secs(8), || fake.borrow().reauths.len() >= 2).await,
                    "renewal never came"
                );
                assert_eq!(seen.borrow()[1], ("vs-nonce-1".to_string(), false));
                assert_eq!(reauth_shapes(&fake)[1], with_user("vs-nonce-1"));
                assert!(
                    eventually(Duration::from_secs(2), || asm
                        .zode_login
                        .expires()
                        .is_some_and(|e| e > first_expiry))
                    .await,
                    "the expiry must move forward"
                );
            })
            .await;
    }

    /// With no renewal, ph logs the user out itself at expiry: a stale user
    /// authority must not stay on the actor.
    #[tokio::test]
    async fn expiry_without_renewal_logs_out() {
        LocalSet::new()
            .run_until(async {
                let (asm, fake) = zode(
                    FakeVsState {
                        auth_lifetime: Some(Duration::from_secs(3)),
                        ..Default::default()
                    },
                    true,
                )
                .await;
                login(&asm, interactive_only_agent().0)
                    .await
                    .expect("login");

                assert!(
                    eventually(Duration::from_secs(10), || !asm.zode_login.is_logged_in()).await,
                    "ph must log out at expiry"
                );
                assert_eq!(last_failure(&asm), Some(AuthFailureReason::LoginExpired));
                assert_eq!(reauth_shapes(&fake).last(), Some(&device_only()));
            })
            .await;
    }

    /// When the VS-API session is replaced the visa service has dropped the
    /// login: ph marks it logged out (`SessionReplaced`) and, with a
    /// resident agent registered, asks it for a new interactive login (q2).
    #[tokio::test]
    async fn session_replaced_logs_out_and_asks_the_agent_again() {
        LocalSet::new()
            .run_until(async {
                let (asm, fake) = zode(FakeVsState::default(), true).await;
                let (agent, seen) = ok_agent();
                login(&asm, agent).await.expect("login");

                session_replaced(&asm);
                assert!(matches!(
                    asm.zode_login.state(),
                    LoginState::LoggedOut {
                        last: Some(AuthFailureReason::SessionReplaced)
                    } | LoginState::LoggingIn
                ));

                assert!(
                    eventually(Duration::from_secs(5), || asm.zode_login.is_logged_in()).await,
                    "the resident agent logs in again"
                );
                assert_eq!(seen.borrow()[1], ("vs-nonce-2".to_string(), true));
                assert_eq!(reauth_shapes(&fake)[1], with_user("vs-nonce-2"));
            })
            .await;
    }

    /// With no agent left (it exited), a replaced session just leaves the
    /// Zode logged out with the reason.
    #[tokio::test]
    async fn session_replaced_without_an_agent_stays_logged_out() {
        LocalSet::new()
            .run_until(async {
                let (asm, fake) = zode(FakeVsState::default(), true).await;
                let (agent, _) = ok_agent();
                login(&asm, agent.clone()).await.expect("login");
                assert!(asm.zode_login.clear_agent_if(&agent));

                session_replaced(&asm);
                tokio::time::sleep(Duration::from_millis(500)).await;
                assert_eq!(last_failure(&asm), Some(AuthFailureReason::SessionReplaced));
                assert_eq!(fake.borrow().login_nonces, 1);
            })
            .await;
    }

    /// q3: a policy `requestAuthentication` for the Zode's own address while
    /// logged in is answered with a silent renewal, not the K2
    /// re-authentication that would drop the user.
    #[tokio::test]
    async fn policy_reauth_while_logged_in_renews() {
        LocalSet::new()
            .run_until(async {
                let (asm, fake) = zode(FakeVsState::default(), true).await;
                let (agent, seen) = ok_agent();
                login(&asm, agent).await.expect("login");
                let own: IpAddr = NODE_ADDR.parse().unwrap();

                let outcome = crate::vss_worker::process_request_authentication(&asm, &[own]);
                assert_eq!(outcome.processed, 1);
                assert!(!outcome.start_self_reauth, "no K2 while logged in");

                assert!(
                    eventually(Duration::from_secs(5), || fake.borrow().reauths.len() == 2).await
                );
                assert_eq!(seen.borrow()[1], ("vs-nonce-1".to_string(), false));
                assert_eq!(reauth_shapes(&fake)[1], with_user("vs-nonce-1"));
                assert_eq!(fake.borrow().connects.len(), 1, "no re-authentication");
                assert!(asm.zode_login.is_logged_in());
            })
            .await;
    }

    /// q3 fallback: when no silent renewal can be had, the policy request
    /// is answered with K2 after all, which replaces the session; the
    /// resident agent is then asked for a new login (q2).
    #[tokio::test]
    async fn policy_reauth_without_a_renewal_falls_back_to_k2() {
        LocalSet::new()
            .run_until(async {
                let (asm, fake) = zode(FakeVsState::default(), true).await;
                let (agent, seen) = interactive_only_agent();
                login(&asm, agent).await.expect("login");
                let own: IpAddr = NODE_ADDR.parse().unwrap();

                crate::vss_worker::process_request_authentication(&asm, &[own]);

                assert!(
                    eventually(Duration::from_secs(10), || seen.borrow().len() == 3).await,
                    "K2, then a new interactive login"
                );
                assert_eq!(fake.borrow().connects.len(), 2, "K2 re-authenticated");
                assert_eq!(seen.borrow()[1], ("vs-nonce-1".to_string(), false));
                assert_eq!(seen.borrow()[2], ("vs-nonce-2".to_string(), true));
                assert!(eventually(Duration::from_secs(5), || asm.zode_login.is_logged_in()).await);
            })
            .await;
    }

    /// A login whose caller goes away (the admin RPC was cancelled, and
    /// ph-cli with it) does not leave the Zode stuck in `LoggingIn`: the
    /// attempt still settles, and a new login works.
    #[tokio::test]
    async fn cancelled_login_does_not_wedge_the_state() {
        LocalSet::new()
            .run_until(async {
                let (asm, _fake) = zode(FakeVsState::default(), true).await;
                // An agent the test can make go away, like ph-cli exiting.
                let (gone_agent, mut agent_rx) =
                    tokio::sync::mpsc::unbounded_channel::<OidcCredentialRequest>();
                let first_asm = asm.clone();
                let first =
                    tokio::task::spawn_local(async move { login(&first_asm, gone_agent).await });
                let request = tokio::time::timeout(Duration::from_secs(5), agent_rx.recv())
                    .await
                    .expect("the agent is asked")
                    .expect("a request");

                first.abort();
                let _ = first.await;
                drop(request);
                drop(agent_rx);
                assert!(
                    eventually(Duration::from_secs(5), || matches!(
                        asm.zode_login.state(),
                        LoginState::LoggedOut { .. }
                    ))
                    .await,
                    "{:?}",
                    asm.zode_login.state()
                );
                login(&asm, ok_agent().0).await.expect("a new login works");
            })
            .await;
    }

    /// An agent that answers every request with [ID_TOKEN] after `delay`.
    fn slow_agent(delay: Duration) -> (AuthAgentHandle, Seen) {
        delayed_agent(delay, |_| Ok(ID_TOKEN.to_string()))
    }

    /// An agent that answers each request with `answer(interactive)`,
    /// after `delay` for a non-interactive one.
    fn delayed_agent(
        delay: Duration,
        answer: impl Fn(bool) -> Result<String, AuthFailureReason> + 'static,
    ) -> (AuthAgentHandle, Seen) {
        let answer = Rc::new(answer);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<OidcCredentialRequest>();
        let seen: Seen = Rc::default();
        let task_seen = seen.clone();
        tokio::task::spawn_local(async move {
            while let Some(req) = rx.recv().await {
                task_seen
                    .borrow_mut()
                    .push((req.nonce.clone(), req.interactive));
                let answer = answer.clone();
                tokio::task::spawn_local(async move {
                    if !req.interactive {
                        tokio::time::sleep(delay).await;
                    }
                    let _ = req.reply.send(answer(req.interactive));
                });
            }
        });
        (tx, seen)
    }

    /// Overlapping renewals (two policy requests) share one: the agent is
    /// asked once and one `reauthorize` goes out. Two refresh-grant tokens
    /// in the same second can carry the same `iat`, which the visa service
    /// refuses.
    #[tokio::test]
    async fn overlapping_renewals_are_coalesced() {
        LocalSet::new()
            .run_until(async {
                let (asm, fake) = zode(FakeVsState::default(), true).await;
                let (agent, seen) = slow_agent(Duration::from_millis(300));
                login(&asm, agent).await.expect("login");
                let own: IpAddr = NODE_ADDR.parse().unwrap();

                crate::vss_worker::process_request_authentication(&asm, &[own]);
                crate::vss_worker::process_request_authentication(&asm, &[own]);

                assert!(
                    eventually(Duration::from_secs(5), || fake.borrow().reauths.len() >= 2).await
                );
                tokio::time::sleep(Duration::from_millis(800)).await;
                assert_eq!(fake.borrow().reauths.len(), 2, "one renewal, not two");
                assert_eq!(seen.borrow().len(), 2, "the agent was asked once to renew");
                assert_eq!(fake.borrow().connects.len(), 1, "no K2");
                assert!(asm.zode_login.is_logged_in());
            })
            .await;
    }

    /// A logout at expiry that the visa service refuses is retried: the
    /// user must not stay on the actor, and until the logout goes through
    /// the Zode does not claim to be logged out.
    #[tokio::test]
    async fn failed_logout_at_expiry_is_retried() {
        LocalSet::new()
            .run_until(async {
                let (asm, fake) = zode(
                    FakeVsState {
                        auth_lifetime: Some(Duration::from_secs(2)),
                        ..Default::default()
                    },
                    true,
                )
                .await;
                login(&asm, interactive_only_agent().0)
                    .await
                    .expect("login");
                fake.borrow_mut()
                    .reauth_errors
                    .push_back(ErrorCode::TemporarilyUnavailable);

                assert!(
                    eventually(Duration::from_secs(5), || fake.borrow().reauths.len() == 2).await,
                    "the logout at expiry"
                );
                assert!(
                    asm.zode_login.is_logged_in(),
                    "the refused logout is pending"
                );

                assert!(
                    eventually(Duration::from_secs(15), || !asm.zode_login.is_logged_in()).await,
                    "the logout is retried"
                );
                assert_eq!(last_failure(&asm), Some(AuthFailureReason::LoginExpired));
                assert_eq!(
                    reauth_shapes(&fake),
                    vec![with_user("vs-nonce-1"), device_only(), device_only()]
                );
            })
            .await;
    }

    /// The first renewal after a login is spaced from the login too: a
    /// refresh token minted in the login's second can carry the login
    /// token's `iat`, which the visa service refuses.
    #[tokio::test]
    async fn first_renewal_is_spaced_from_the_login() {
        LocalSet::new()
            .run_until(async {
                let (asm, fake) = zode(FakeVsState::default(), true).await;
                login(&asm, ok_agent().0).await.expect("login");
                let logged_in = tokio::time::Instant::now();
                let own: IpAddr = NODE_ADDR.parse().unwrap();

                crate::vss_worker::process_request_authentication(&asm, &[own]);
                assert!(
                    eventually(Duration::from_secs(5), || fake.borrow().reauths.len() == 2).await
                );
                assert!(
                    logged_in.elapsed() >= Duration::from_millis(800),
                    "renewed {:?} after the login",
                    logged_in.elapsed()
                );
            })
            .await;
    }

    /// A renewal that lands while the expiry logout waits for it wins: the
    /// renewed user is not logged out.
    #[tokio::test]
    async fn expiry_does_not_log_out_a_login_renewed_meanwhile() {
        LocalSet::new()
            .run_until(async {
                let (asm, fake) = zode(
                    FakeVsState {
                        auth_lifetime: Some(Duration::from_secs(3)),
                        ..Default::default()
                    },
                    true,
                )
                .await;
                // The timer's renewal is refused; the policy renewal works.
                let calls = std::cell::Cell::new(0u32);
                let (agent, _) = agent(move |interactive| {
                    if interactive {
                        return Some(Ok(ID_TOKEN.to_string()));
                    }
                    calls.set(calls.get() + 1);
                    Some(if calls.get() == 1 {
                        Err(AuthFailureReason::AgentError("not yet".to_string()))
                    } else {
                        Ok(ID_TOKEN.to_string())
                    })
                });
                login(&asm, agent).await.expect("login");
                {
                    let mut st = fake.borrow_mut();
                    st.auth_lifetime = Some(Duration::from_secs(60));
                    st.reauth_delay = Some(Duration::from_millis(1200));
                }
                let expires = asm.zode_login.expires().unwrap();
                let policy_at = expires - Duration::from_millis(400);
                tokio::time::sleep(
                    policy_at
                        .duration_since(SystemTime::now())
                        .unwrap_or_default(),
                )
                .await;

                let own: IpAddr = NODE_ADDR.parse().unwrap();
                crate::vss_worker::process_request_authentication(&asm, &[own]);
                tokio::time::sleep(Duration::from_secs(3)).await;

                assert!(
                    asm.zode_login.is_logged_in(),
                    "{:?}",
                    asm.zode_login.state()
                );
                assert!(
                    !reauth_shapes(&fake).contains(&device_only()),
                    "no logout: {:?}",
                    reauth_shapes(&fake)
                );
            })
            .await;
    }

    /// A logout whose caller goes away still settles the state: the visa
    /// service drops the user either way once the request is queued.
    #[tokio::test]
    async fn cancelled_logout_still_logs_out() {
        LocalSet::new()
            .run_until(async {
                let (asm, fake) = zode(FakeVsState::default(), true).await;
                login(&asm, ok_agent().0).await.expect("login");
                fake.borrow_mut().reauth_delay = Some(Duration::from_millis(500));

                let task_asm = asm.clone();
                let caller = tokio::task::spawn_local(async move { logout(&task_asm).await });
                assert!(
                    eventually(Duration::from_secs(5), || fake.borrow().reauths.len() == 2).await
                );
                caller.abort();
                let _ = caller.await;

                assert!(
                    eventually(Duration::from_secs(5), || !asm.zode_login.is_logged_in()).await,
                    "{:?}",
                    asm.zode_login.state()
                );
                assert_eq!(last_failure(&asm), None);
            })
            .await;
    }

    /// A policy renewal that fails after its login ended (the user logged
    /// out and someone logged in again) does not fall back to K2, which
    /// would drop the new login.
    #[tokio::test]
    async fn stale_policy_renewal_failure_does_not_k2_a_new_login() {
        LocalSet::new()
            .run_until(async {
                let (asm, fake) = zode(FakeVsState::default(), true).await;
                let (first, _) = delayed_agent(Duration::from_millis(500), |interactive| {
                    if interactive {
                        Ok(ID_TOKEN.to_string())
                    } else {
                        Err(AuthFailureReason::AgentError(
                            "no refresh token".to_string(),
                        ))
                    }
                });
                login(&asm, first).await.expect("first login");
                // Past the renewal spacing, so the renewal asks the agent.
                tokio::time::sleep(MIN_RENEWAL_SPACING + Duration::from_millis(100)).await;
                let own: IpAddr = NODE_ADDR.parse().unwrap();
                crate::vss_worker::process_request_authentication(&asm, &[own]);
                tokio::time::sleep(Duration::from_millis(100)).await;

                logout(&asm).await.expect("logout");
                login(&asm, ok_agent().0).await.expect("second login");
                tokio::time::sleep(Duration::from_millis(1500)).await;

                assert_eq!(fake.borrow().connects.len(), 1, "no K2");
                assert!(
                    asm.zode_login.is_logged_in(),
                    "{:?}",
                    asm.zode_login.state()
                );
            })
            .await;
    }

    /// A renewal stuck on an ended login's agent does not hold up the next
    /// login's renewals.
    #[tokio::test]
    async fn stale_stuck_renewal_does_not_block_a_new_login() {
        LocalSet::new()
            .run_until(async {
                let (asm, fake) = zode(FakeVsState::default(), true).await;
                // Logs in, then never answers a silent renewal.
                let (stuck, _) = agent(|interactive| interactive.then(|| Ok(ID_TOKEN.to_string())));
                login(&asm, stuck).await.expect("first login");
                tokio::time::sleep(MIN_RENEWAL_SPACING + Duration::from_millis(100)).await;
                let own: IpAddr = NODE_ADDR.parse().unwrap();
                crate::vss_worker::process_request_authentication(&asm, &[own]);
                tokio::time::sleep(Duration::from_millis(100)).await;

                logout(&asm).await.expect("logout");
                login(&asm, ok_agent().0).await.expect("second login");
                tokio::time::sleep(MIN_RENEWAL_SPACING + Duration::from_millis(100)).await;
                let before = fake.borrow().reauths.len();
                crate::vss_worker::process_request_authentication(&asm, &[own]);

                assert!(
                    eventually(Duration::from_secs(3), || fake.borrow().reauths.len()
                        > before)
                    .await,
                    "the new login's renewal is blocked"
                );
            })
            .await;
    }

    /// A policy renewal that shortens the login wakes the timer, which then
    /// logs out at the new expiry instead of sleeping on the old one.
    #[tokio::test]
    async fn a_shortened_renewal_rearms_the_timer() {
        LocalSet::new()
            .run_until(async {
                let (asm, fake) = zode(FakeVsState::default(), true).await;
                // One silent renewal works; later ones are refused.
                let calls = std::cell::Cell::new(0u32);
                let (agent, _) = agent(move |interactive| {
                    if interactive {
                        return Some(Ok(ID_TOKEN.to_string()));
                    }
                    calls.set(calls.get() + 1);
                    Some(if calls.get() == 1 {
                        Ok(ID_TOKEN.to_string())
                    } else {
                        Err(AuthFailureReason::AgentError(
                            "no refresh token".to_string(),
                        ))
                    })
                });
                login(&asm, agent).await.expect("login");
                tokio::time::sleep(MIN_RENEWAL_SPACING + Duration::from_millis(100)).await;
                fake.borrow_mut().auth_lifetime = Some(Duration::from_secs(3));
                let own: IpAddr = NODE_ADDR.parse().unwrap();
                crate::vss_worker::process_request_authentication(&asm, &[own]);

                assert!(
                    eventually(Duration::from_secs(10), || !asm.zode_login.is_logged_in()).await,
                    "the timer must follow the shortened expiry"
                );
                assert_eq!(last_failure(&asm), Some(AuthFailureReason::LoginExpired));
            })
            .await;
    }

    /// A renewal waiting on an agent that never answers does not hold the
    /// logout past the expiry.
    #[tokio::test]
    async fn a_silent_agent_does_not_delay_the_expiry_logout() {
        LocalSet::new()
            .run_until(async {
                let (asm, _fake) = zode(
                    FakeVsState {
                        auth_lifetime: Some(Duration::from_secs(3)),
                        ..Default::default()
                    },
                    true,
                )
                .await;
                let (silent, _) =
                    agent(|interactive| interactive.then(|| Ok(ID_TOKEN.to_string())));
                login(&asm, silent).await.expect("login");

                assert!(
                    eventually(Duration::from_millis(4500), || !asm
                        .zode_login
                        .is_logged_in())
                    .await,
                    "logged out late: {:?}",
                    asm.zode_login.state()
                );
            })
            .await;
    }

    /// `ph-cli login-status` shows the state, the issuer and the time left,
    /// whether an agent is registered, and the last failure.
    #[test]
    fn status_text_names_state_issuer_expiry_agent_and_failure() {
        let now = SystemTime::now();
        let logged_in = LoginState::LoggedIn {
            idp: crate::auth::OidcIdpInfo {
                issuer: ISSUER.to_string(),
                client_id: "c".to_string(),
                client_secret: None,
                scopes: Vec::new(),
                allow_offline_access: true,
            },
            nonce: "secret-nonce".to_string(),
            granted_at: now,
            expires: now + Duration::from_secs(90),
        };
        let text = format_status(&logged_in, true, now);
        assert_eq!(
            text,
            format!(
                "State: logged in\nIssuer: {ISSUER}\nExpires in: 90s\nAuth agent: registered\n"
            )
        );
        assert!(!text.contains("secret-nonce"), "nonces are never shown");

        let text = format_status(
            &LoginState::LoggedOut {
                last: Some(AuthFailureReason::SessionReplaced),
            },
            false,
            now,
        );
        assert_eq!(
            text,
            "State: logged out\nAuth agent: none\nLast failure: SessionReplaced\n"
        );
        assert_eq!(
            format_status(&LoginState::LoggingIn, true, now),
            "State: logging in\nAuth agent: registered\n"
        );
    }
}
