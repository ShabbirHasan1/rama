//! Middleware that validates if a request has the appropriate Proxy Authorisation.
//!
//! If the request is not authorized a `407 Proxy Authentication Required` response will be sent.

use crate::headers::authorization::Authority;
use crate::headers::authorization::AuthoritySync;
use crate::headers::authorization::UserCredStore;
use crate::headers::authorization::UserCredStoreBackend;
use crate::headers::{HeaderMapExt, ProxyAuthorization};
use crate::layer::firewall::FirewallLayer;
use crate::layer::firewall::FirewallStoreBackend;
use crate::{Request, Response, StatusCode};
use rama_core::error::{BoxError, ErrorContext as _};
use rama_core::extensions::{Extensions, ExtensionsMut, ExtensionsRef};
use rama_core::telemetry::tracing;
use rama_core::telemetry::tracing::warn;
use rama_core::{Layer, Service};
use rama_http_headers::authorization::UserCredInfo;
use rama_http_types::body::OptionalBody;
use rama_net::stream::SocketInfo;
use rama_net::user::{Basic, UserId};
use rama_utils::macros::define_inner_service_accessors;
use rama_utils::str::smol_str::ToSmolStr as _;
use std::fmt;

/// Layer that applies the [`CustomProxyAuthService`] middleware which apply a timeout to requests.
///
/// See the [module docs](super) for an example.
pub struct CustomProxyAuthLayer {
    proxy_auth: UserCredStore<Basic>,
    allow_anonymous: bool,
    firewall_layer: FirewallLayer,
}

impl fmt::Debug for CustomProxyAuthLayer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("CustomProxyAuthLayer")
            .field("proxy_auth", &self.proxy_auth)
            .field("allow_anonymous", &self.allow_anonymous)
            .field("firewall_layer", &self.firewall_layer)
            .finish()
    }
}

impl Clone for CustomProxyAuthLayer {
    fn clone(&self) -> Self {
        Self {
            proxy_auth: self.proxy_auth.clone(),
            allow_anonymous: self.allow_anonymous,
            firewall_layer: self.firewall_layer.clone(),
        }
    }
}

impl CustomProxyAuthLayer {
    /// Creates a new [`CustomProxyAuthLayer`] with UserCredStore.
    #[must_use]
    pub const fn new(proxy_auth: UserCredStore<Basic>, firewall_layer: FirewallLayer) -> Self {
        Self {
            proxy_auth,
            allow_anonymous: false,
            firewall_layer,
        }
    }

    /// Allow anonymous requests.
    pub fn set_allow_anonymous(&mut self, allow_anonymous: bool) -> &mut Self {
        self.allow_anonymous = allow_anonymous;
        self
    }

    /// Allow anonymous requests.
    #[must_use]
    pub fn with_allow_anonymous(mut self, allow_anonymous: bool) -> Self {
        self.allow_anonymous = allow_anonymous;
        self
    }
}

impl<S> Layer<S> for CustomProxyAuthLayer {
    type Service = CustomProxyAuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CustomProxyAuthService::new(self.proxy_auth.clone(), self.firewall_layer.clone(), inner)
            .with_allow_anonymous(self.allow_anonymous)
    }

    fn into_layer(self, inner: S) -> Self::Service {
        CustomProxyAuthService::new(self.proxy_auth, self.firewall_layer, inner)
            .with_allow_anonymous(self.allow_anonymous)
    }
}

/// Middleware that validates if a request has the appropriate Proxy Authorisation.
///
/// If the request is not authorized a `407 Proxy Authentication Required` response will be sent.
/// If `allow_anonymous` is set to `true` then requests without a Proxy Authorization header will be
/// allowed and the user will be authoized as [`UserId::Anonymous`].
///
/// See the [module docs](self) for an example.
pub struct CustomProxyAuthService<S> {
    proxy_auth: UserCredStore<Basic>,
    allow_anonymous: bool,
    firewall_layer: FirewallLayer,
    inner: S,
}

impl<S> CustomProxyAuthService<S> {
    /// Creates a new [`CustomProxyAuthService`].
    #[must_use]
    pub const fn new(
        proxy_auth: UserCredStore<Basic>,
        firewall_layer: FirewallLayer,
        inner: S,
    ) -> Self {
        Self {
            proxy_auth,
            allow_anonymous: false,
            firewall_layer,
            inner,
        }
    }

    /// Allow anonymous requests.
    pub fn set_allow_anonymous(&mut self, allow_anonymous: bool) -> &mut Self {
        self.allow_anonymous = allow_anonymous;
        self
    }

    /// Allow anonymous requests.
    #[must_use]
    pub fn with_allow_anonymous(mut self, allow_anonymous: bool) -> Self {
        self.allow_anonymous = allow_anonymous;
        self
    }

    define_inner_service_accessors!();
}

impl<S: fmt::Debug> fmt::Debug for CustomProxyAuthService<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CustomProxyAuthService")
            .field("proxy_auth", &self.proxy_auth)
            .field("allow_anonymous", &self.allow_anonymous)
            .field("firewall_layer", &self.firewall_layer)
            .field("inner", &self.inner)
            .finish()
    }
}

impl<S: Clone> Clone for CustomProxyAuthService<S> {
    fn clone(&self) -> Self {
        Self {
            proxy_auth: self.proxy_auth.clone(),
            allow_anonymous: self.allow_anonymous,
            firewall_layer: self.firewall_layer.clone(),
            inner: self.inner.clone(),
        }
    }
}

pub static WARNING_MESSAGE: &str = "
CRITICAL: Proceeding may cause irreversible state desynchronization or permanent data loss. This event has been logged for security audit;ACCESS DENIED: This path is not a place of honor. Nothing valued is here. Your current request parameters emanate instability;STOP: Violation of authentication protocol detected. Unauthorized traversal will result in immediate IP blacklisting and credential revocation;UNSTABLE PATH: Continued interaction with this malformed request will trigger automated defensive countermeasures;VOID: You are peering into the abyss, and it is beginning to peer back. Your request is an affront to the architect’s design;DO NOT PROCEED: The following path is NOT a place of honor. No value is found here. What you seek has already found you;RUN: You’ve opened a door that cannot be closed. We’ve logged your ip,  location and other details. We suggest you look behind you before the timeout expires;SYSTEM MALIGNANCY: Your request has introduced a parasitic state. The server is hemorrhaging memory. Cease all traversal immediately.";

thread_local! {
    static API_KEY_BUFFER: std::cell::RefCell<String> = std::cell::RefCell::new(String::with_capacity(256));
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for CustomProxyAuthService<S>
where
    S: Service<Request<ReqBody>, Output = Response<ResBody>, Error: Into<BoxError>>,
    ReqBody: Send + 'static,
    ResBody: Default + Send + 'static,
{
    type Output = Response<OptionalBody<ResBody>>;
    type Error = BoxError;

    async fn serve(&self, mut req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        let ip_addr = req
            .extensions()
            .get::<SocketInfo>()
            .context("no socket info found")?
            .peer_addr()
            .ip_addr
            .to_smolstr();

        let ip_wise_violation = API_KEY_BUFFER.with(|buf| {
            let mut buffer = buf.borrow_mut();
            buffer.push_str("::");
            buffer.push_str(ip_addr.as_str());
            buffer.push_str("::");
            buffer.to_owned()
        });

        let is_ip_in_allowed_list = match &self.firewall_layer.allowed_list.backend {
            FirewallStoreBackend::RwLock(store) => {
                let data_guard = store.read().await;
                data_guard.contains(ip_addr.as_str())
            }
            FirewallStoreBackend::ArcSwap(store) => {
                let data_guard = store.load();
                data_guard.contains(ip_addr.as_str())
            }
            FirewallStoreBackend::ArcShift(store) => {
                let data_guard = store.shared_get();
                data_guard.contains(ip_addr.as_str())
            }
        };

        if !is_ip_in_allowed_list && req.method() != http::Method::CONNECT {
            let ban_info = self
                .firewall_layer
                .firewall
                .record_violation(&ip_addr)
                .await
                .context("ip address record violation entry ban_info not found")?;
            let ban_time = ban_info.calculate_ttl();
            warn!(ip_addr = %ip_addr, ban_info = ?ban_info, ban_time = ?ban_time, "Invalid method for CONNECT request, Banned IP Address with Ban Info");
            return Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .header(http::header::WARNING, WARNING_MESSAGE)
                .header(http::header::RETRY_AFTER, format!("{ban_time:?}"))
                .body(OptionalBody::none())
                .context("create auth-required response")
                .context_field("ip_addr", ip_addr);
        }

        let credentials = req
            .headers()
            .typed_get::<ProxyAuthorization<Basic>>()
            .map(|h| h.0)
            .or_else(|| req.extensions().get::<Basic>().cloned());

        match credentials {
            Some(creds) => {
                tracing::trace!("Proxy credentials found");
                let api_key = creds.username().to_owned();
                let is_in_allowed_list = match &self.firewall_layer.allowed_list.backend {
                    FirewallStoreBackend::RwLock(store) => {
                        let data_guard = store.read().await;
                        data_guard.contains(api_key.as_str())
                    }
                    FirewallStoreBackend::ArcSwap(store) => {
                        let data_guard = store.load();
                        data_guard.contains(api_key.as_str())
                    }
                    FirewallStoreBackend::ArcShift(store) => {
                        let data_guard = store.shared_get();
                        data_guard.contains(api_key.as_str())
                    }
                };

                let is_in_blocked_list = match &self.firewall_layer.blocked_list.backend {
                    FirewallStoreBackend::RwLock(store) => {
                        let data_guard = store.read().await;
                        data_guard.contains(api_key.as_str())
                    }
                    FirewallStoreBackend::ArcSwap(store) => {
                        let data_guard = store.load();
                        data_guard.contains(api_key.as_str())
                    }
                    FirewallStoreBackend::ArcShift(store) => {
                        let data_guard = store.shared_get();
                        data_guard.contains(api_key.as_str())
                    }
                };

                if is_in_blocked_list {
                    warn!(api_key = %api_key, "Found Banned API_KEY in blocked list");
                    return Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .header(http::header::WARNING, WARNING_MESSAGE)
                        .body(OptionalBody::none())
                        .context("create banned api_key response")
                        .context_field("api_key", api_key);
                }
                let is_un_banned = self.firewall_layer.firewall.is_banned(&api_key).await;
                let is_ip_banned = self
                    .firewall_layer
                    .firewall
                    .is_banned(&ip_wise_violation)
                    .await;
                if !is_in_allowed_list && let Some(_un_ban_info) = is_un_banned {
                    let ban_info = self
                        .firewall_layer
                        .firewall
                        .record_violation(&api_key)
                        .await
                        .context("api_key record violation entry ban_info not found")?;
                    let ban_time = ban_info.calculate_ttl();
                    warn!(api_key = %api_key, ip_addr = %ip_addr, ban_info = ?ban_info, ban_time = ?ban_time, "Dropping Connection For Blocked API_KEY, ReBanned API_KEY With Updated Ban Info");

                    if let Some(ip_ban_info) = is_ip_banned
                        && ip_ban_info.violation_count >= 3
                    {
                        for _ in 0..ip_ban_info.violation_count {
                            self.firewall_layer
                                .firewall
                                .record_violation(&ip_addr)
                                .await
                                .context("ip address record violation entry ban_info not found")?;
                        }
                        let ban_time = {
                            let seconds = 1u64 << ip_ban_info.violation_count.min(12);
                            std::time::Duration::from_secs(seconds * 60)
                        };
                        warn!(ip_addr = %ip_addr, ban_time = ?ban_time, "Multiple Failed Attempts, Possible BruteForce Attack with Worng Credentials, Banned IP Address with Ban Info");
                    }

                    return Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .header(http::header::WARNING, WARNING_MESSAGE)
                        .header(http::header::RETRY_AFTER, format!("{ban_time:?}"))
                        .body(OptionalBody::none())
                        .context("drop connection for blocked api_key")
                        .context_field("api_key", api_key);
                }
                let auth_result = match &self.proxy_auth.backend {
                    UserCredStoreBackend::RwLock(store) => {
                        let data_guard = store.read().await;
                        <Vec<UserCredInfo<Basic>> as Authority<Basic, ()>>::authorized(
                            &data_guard,
                            creds,
                        )
                        .await
                    }
                    UserCredStoreBackend::ArcSwap(store) => {
                        let data_guard = store.load();
                        <Vec<UserCredInfo<Basic>> as Authority<Basic, ()>>::authorized(
                            &data_guard,
                            creds,
                        )
                        .await
                    }
                    UserCredStoreBackend::ArcShift(store) => {
                        let mut extension = Extensions::new();
                        let data_guard = store.shared_get();
                        if <Vec<UserCredInfo<Basic>> as AuthoritySync<Basic, ()>>::authorized(
                            &data_guard,
                            &mut extension,
                            &creds,
                        ) {
                            Some(extension)
                        } else {
                            None
                        }
                    }
                    UserCredStoreBackend::RwLockHashmap(store) => {
                        let data_guard = store.read().await;
                        if let Some(user_cred_info) = data_guard.0.get(&creds)
                            && let Some(ext) =
                                <UserCredInfo<Basic> as Authority<Basic, ()>>::authorized(
                                    user_cred_info,
                                    creds,
                                )
                                .await
                        {
                            Some(ext)
                        } else {
                            None
                        }
                    }
                    UserCredStoreBackend::ArcSwapHashmap(store) => {
                        let data_guard = store.load();
                        if let Some(user_cred_info) = data_guard.0.get(&creds)
                            && let Some(ext) =
                                <UserCredInfo<Basic> as Authority<Basic, ()>>::authorized(
                                    user_cred_info,
                                    creds,
                                )
                                .await
                        {
                            Some(ext)
                        } else {
                            None
                        }
                    }
                    UserCredStoreBackend::ArcShiftHashmap(store) => {
                        let mut extension = Extensions::new();
                        let data_guard = store.shared_get();
                        if let Some(user_cred_info) = data_guard.0.get(&creds)
                            && <UserCredInfo<Basic> as AuthoritySync<Basic, ()>>::authorized(
                                user_cred_info,
                                &mut extension,
                                &creds,
                            )
                        {
                            Some(extension)
                        } else {
                            None
                        }
                    }
                };

                tracing::trace!(
                    auth_result = ?auth_result,
                    "Proxy credentials checked"
                );

                if let Some(ext) = auth_result {
                    req.extensions_mut().extend(ext);
                    Ok(self
                        .inner
                        .serve(req)
                        .await
                        .map_err(|err| BoxError::from(err.into()))?
                        .map(OptionalBody::some))
                } else {
                    let ban_info = self
                        .firewall_layer
                        .firewall
                        .record_violation(&api_key)
                        .await
                        .context("api_key record_violation record info not found")?;
                    let ban_time = ban_info.calculate_ttl();
                    warn!(api_key = %api_key, ban_info = ?ban_info, ban_time = ?ban_time, "Possible BruteForce Attack with Worng Credentials, Banned API_KEY with Ban Info");
                    let _ban_info = self
                        .firewall_layer
                        .firewall
                        .record_violation(&ip_wise_violation)
                        .await
                        .context("ip_wise_violation record_violation record info not found")?;
                    Ok(Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .header(http::header::WARNING, WARNING_MESSAGE)
                        .header(http::header::RETRY_AFTER, format!("{ban_time:?}"))
                        .body(OptionalBody::none())
                        .context("create banned api_key response")
                        .context_field("api_key", api_key)?)
                    // Ok(Response::builder()
                    // .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                    // .header(PROXY_AUTHENTICATE, "Basic")
                    // .header(http::header::WARNING, WARNING_MESSAGE)
                    // .body(OptionalBody::none())
                    // .context("create auth-required response")?),
                }
            }
            None => {
                if self.allow_anonymous || !is_ip_in_allowed_list {
                    req.extensions_mut().insert(UserId::Anonymous);
                    Ok(self
                        .inner
                        .serve(req)
                        .await
                        .map_err(|err| BoxError::from(err.into()))?
                        .map(OptionalBody::some))
                } else {
                    let ban_info = self
                        .firewall_layer
                        .firewall
                        .record_violation(&ip_addr)
                        .await
                        .context("ip address record violation record info not found")?;
                    let ban_time = ban_info.calculate_ttl();
                    warn!(ip_addr = %ip_addr, ban_info = ?ban_info, ban_time = ?ban_time, "Credentials is a must and required, Banned IP Address with Ban Info");
                    Ok(Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        // .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                        // .header(PROXY_AUTHENTICATE, "Basic")
                        .header(http::header::WARNING, WARNING_MESSAGE)
                        .header(http::header::RETRY_AFTER, format!("{ban_time:?}"))
                        .body(OptionalBody::none())
                        .context("create auth-required response")?)
                }
            }
        }
    }
}
