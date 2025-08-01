//! Authorization header and types.

use std::net::IpAddr;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use arc_swap::{ArcSwap, ArcSwapAny};
use arcshift::ArcShift;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as ENGINE;

use rama_core::context::Extensions;
use rama_core::telemetry::tracing;
use rama_core::username::{UsernameLabelParser, parse_username};
use rama_http_types::{HeaderName, HeaderValue};
use rama_net::address::SocketAddress;
use rama_net::user::authority::{AuthorizeResult, Authorizer, StaticAuthorizer, Unauthorized};
use rama_net::user::{Basic, Bearer, UserId};
use tokio::sync::RwLock;

use crate::{Error, HeaderDecode, HeaderEncode, TypedHeader};

/// `Authorization` header, defined in [RFC7235](https://tools.ietf.org/html/rfc7235#section-4.2)
///
/// The `Authorization` header field allows a user agent to authenticate
/// itself with an origin server -- usually, but not necessarily, after
/// receiving a 401 (Unauthorized) response.  Its value consists of
/// credentials containing the authentication information of the user
/// agent for the realm of the resource being requested.
///
/// # ABNF
///
/// ```text
/// Authorization = credentials
/// ```
///
/// # Example values
/// * `Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==`
/// * `Bearer fpKL54jvWmEGVoRdCNjG`
///
/// # Examples
///
/// ```
/// use rama_http_headers::Authorization;
/// use rama_net::user::{Basic, Bearer};
///
/// let basic = Authorization::new(Basic::new_static("Aladdin", "open sesame"));
/// let bearer = Authorization::new(Bearer::new_static("some-opaque-token"));
/// ```
///
#[derive(Clone, PartialEq, Debug)]
pub struct Authorization<C>(pub C);

impl<C> Authorization<C> {
    /// Create a new authorization header.
    pub fn new(credentials: C) -> Self {
        Self(credentials)
    }

    pub fn credentials(&self) -> &C {
        &self.0
    }

    pub fn into_inner(self) -> C {
        self.0
    }
}

impl<C> AsRef<C> for Authorization<C> {
    fn as_ref(&self) -> &C {
        &self.0
    }
}

impl<C> Deref for Authorization<C> {
    type Target = C;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<C> DerefMut for Authorization<C> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<C: Credentials> TypedHeader for Authorization<C> {
    fn name() -> &'static HeaderName {
        &::rama_http_types::header::AUTHORIZATION
    }
}

impl<C: Credentials> HeaderDecode for Authorization<C> {
    fn decode<'i, I: Iterator<Item = &'i HeaderValue>>(values: &mut I) -> Result<Self, Error> {
        values
            .next()
            .and_then(|val| {
                let slice = val.as_bytes();
                if slice.len() > C::SCHEME.len()
                    && slice[C::SCHEME.len()] == b' '
                    && slice[..C::SCHEME.len()].eq_ignore_ascii_case(C::SCHEME.as_bytes())
                {
                    C::decode(val).map(Authorization)
                } else {
                    None
                }
            })
            .ok_or_else(Error::invalid)
    }
}

impl<C: Credentials> HeaderEncode for Authorization<C> {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        let mut value = self.0.encode();
        value.set_sensitive(true);
        debug_assert!(
            value.as_bytes().starts_with(C::SCHEME.as_bytes()),
            "Credentials::encode should include its scheme: scheme = {:?}, encoded = {:?}",
            C::SCHEME,
            value,
        );

        values.extend(::std::iter::once(value));
    }
}

/// Credentials to be used in the `Authorization` header.
pub trait Credentials: Sized {
    /// The scheme identify the format of these credentials.
    ///
    /// This is the static string that always prefixes the actual credentials,
    /// like `"Basic"` in basic authorization.
    const SCHEME: &'static str;

    /// Try to decode the credentials from the `HeaderValue`.
    ///
    /// The `SCHEME` will be the first part of the `value`.
    fn decode(value: &HeaderValue) -> Option<Self>;

    /// Encode the credentials to a `HeaderValue`.
    ///
    /// The `SCHEME` must be the first part of the `value`.
    fn encode(&self) -> HeaderValue;
}

impl Credentials for Basic {
    const SCHEME: &'static str = "Basic";

    fn decode(value: &HeaderValue) -> Option<Self> {
        let value = value.as_ref();

        if value.len() <= Self::SCHEME.len() + 1 {
            tracing::trace!(
                "Basic credentials failed to decode: invalid scheme length in basic str"
            );
            return None;
        }
        if !value[..Self::SCHEME.len()].eq_ignore_ascii_case(Self::SCHEME.as_bytes()) {
            tracing::trace!("Basic credentials failed to decode: invalid scheme in basic str");
            return None;
        }

        let bytes = &value[Self::SCHEME.len() + 1..];
        let Some(non_space_pos) = bytes.iter().position(|b| *b != b' ') else {
            tracing::trace!(
                "Basic credentials failed to decode: missing space separator in basic str"
            );
            return None;
        };

        let bytes = &bytes[non_space_pos..];

        let bytes = ENGINE
            .decode(bytes)
            .inspect_err(|err| {
                tracing::trace!("Basic credentials failed to decode: base64 decode: {err:?}");
            })
            .ok()?;

        let decoded = String::from_utf8(bytes)
            .inspect_err(|err| {
                tracing::trace!("Basic credentials failed to decode: utf8 validation: {err:?}");
            })
            .ok()?;

        decoded
            .parse()
            .inspect_err(|err| {
                tracing::trace!("Basic credentials failed to decode: str parse: {err:?}");
            })
            .ok()
    }

    fn encode(&self) -> HeaderValue {
        let mut encoded = format!("{} ", Self::SCHEME);
        ENGINE.encode_string(self.to_string(), &mut encoded);
        HeaderValue::try_from(encoded).unwrap()
    }
}

impl Credentials for Bearer {
    const SCHEME: &'static str = "Bearer";

    fn decode(value: &HeaderValue) -> Option<Self> {
        let value = value.as_ref();

        if value.len() <= Self::SCHEME.len() + 1 {
            tracing::trace!("Bearer credentials failed to decode: invalid bearer scheme length");
            return None;
        }
        if !value[..Self::SCHEME.len()].eq_ignore_ascii_case(Self::SCHEME.as_bytes()) {
            tracing::trace!("Bearer credentials failed to decode: invalid bearer scheme");
            return None;
        }

        let bytes = &value[Self::SCHEME.len() + 1..];

        let Some(non_space_pos) = bytes.iter().position(|b| *b != b' ') else {
            tracing::trace!("Bearer credentials failed to decode: no token found");
            return None;
        };

        let bytes = &bytes[non_space_pos..];

        let s = std::str::from_utf8(bytes)
            .inspect_err(|err| {
                tracing::trace!("Bearer credentials failed to decode: {err:?}");
            })
            .ok()?;

        Self::try_from(s.to_owned())
            .inspect_err(|err| {
                tracing::trace!("Bearer credentials failed to decode: {err:?}");
            })
            .ok()
    }

    fn encode(&self) -> HeaderValue {
        HeaderValue::try_from(format!("{} {}", Self::SCHEME, self.token())).unwrap()
    }
}

/// The `Authority` trait is used to determine if a set of [`Credential`]s are authorized.
///
/// [`Credential`]: rama_http_headers::authorization::Credentials
pub trait Authority<C, L>: Send + Sync + 'static {
    /// Returns `true` if the credentials are authorized, otherwise `false`.
    fn authorized(&self, credentials: C) -> impl Future<Output = Option<Extensions>> + Send + '_;
}

/// A synchronous version of [`Authority`], to be used for primitive implementations.
pub trait AuthoritySync<C, L>: Send + Sync + 'static {
    /// Returns `true` if the credentials are authorized, otherwise `false`.
    fn authorized(&self, ext: &mut Extensions, credentials: &C) -> bool;
}

impl<A, C, L> Authority<C, L> for A
where
    A: AuthoritySync<C, L>,
    C: Credentials + Send + 'static,
    L: 'static,
{
    async fn authorized(&self, credentials: C) -> Option<Extensions> {
        let mut ext = Extensions::new();
        if self.authorized(&mut ext, &credentials) {
            Some(ext)
        } else {
            None
        }
    }
}

impl<T: UsernameLabelParser> AuthoritySync<Self, T> for Basic {
    fn authorized(&self, ext: &mut Extensions, credentials: &Self) -> bool {
        let username = credentials.username();
        let password = credentials.password();

        if password != self.password() {
            return false;
        }

        let mut parser_ext = Extensions::new();
        let username = match parse_username(&mut parser_ext, T::default(), username) {
            Ok(t) => t,
            Err(err) => {
                tracing::trace!("failed to parse username: {:?}", err);
                return if self == credentials {
                    ext.insert(UserId::Username(username.to_owned()));
                    true
                } else {
                    false
                };
            }
        };

        if username != self.username() {
            return false;
        }

        ext.extend(parser_ext);
        ext.insert(UserId::Username(username));
        true
    }
}

impl<C, L, T, const N: usize> AuthoritySync<C, L> for [T; N]
where
    C: Credentials + Send + 'static,
    T: AuthoritySync<C, L>,
{
    fn authorized(&self, ext: &mut Extensions, credentials: &C) -> bool {
        self.iter().any(|t| t.authorized(ext, credentials))
    }
}

impl<C, L, T> AuthoritySync<C, L> for Vec<T>
where
    C: Credentials + Send + 'static,
    T: AuthoritySync<C, L>,
{
    fn authorized(&self, ext: &mut Extensions, credentials: &C) -> bool {
        self.iter().any(|t| t.authorized(ext, credentials))
    }
}

impl<C, L, T> AuthoritySync<C, L> for Arc<T>
where
    C: Credentials + Send + 'static,
    T: AuthoritySync<C, L>,
{
    fn authorized(&self, ext: &mut Extensions, credentials: &C) -> bool {
        (**self).authorized(ext, credentials)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserCredInfo<A> {
    pub credential: A,
    pub primary_ip: IpAddr,
    pub secondary_ip: IpAddr,
}

impl UserCredInfo<Basic> {
    #[must_use]
    pub fn new_static(
        username: &'static str,
        password: &'static str,
        primary_ip: IpAddr,
        secondary_ip: IpAddr,
    ) -> Self {
        Self {
            credential: Basic::new_static(username, password),
            primary_ip,
            secondary_ip,
        }
    }

    #[must_use]
    pub fn primary_connector(&self) -> SocketAddress {
        SocketAddress::new(self.primary_ip, 0)
    }

    #[must_use]
    pub fn secondary_connector(&self) -> SocketAddress {
        SocketAddress::new(self.secondary_ip, 0)
    }

    #[must_use]
    pub fn into_authorizer(self) -> StaticAuthorizer<Basic> {
        StaticAuthorizer::new(self.credential)
    }
}

impl<C: PartialEq + Clone + Send + Sync + 'static> Authorizer<C> for UserCredInfo<C> {
    type Error = Unauthorized;

    async fn authorize(&self, credentials: C) -> AuthorizeResult<C, Self::Error> {
        let mut ext = Extensions::new();
        let result = credentials.eq(&self.credential);
        let AuthorizeResult {
            credentials: c,
            result,
        } = result.authorize(credentials).await;
        match result {
            Ok(maybe_ext) => {
                ext.insert(self.clone());
                if maybe_ext.is_none() {
                    return AuthorizeResult {
                        credentials: c,
                        result: Ok(Some(ext)),
                    };
                }
                AuthorizeResult {
                    credentials: c,
                    result: Ok(maybe_ext),
                }
            }
            Err(err) => AuthorizeResult {
                credentials: c,
                result: Err(err),
            },
        }
    }

    fn authorize_sync(&self, credentials: C) -> AuthorizeResult<C, Self::Error> {
        let mut ext = Extensions::new();
        let result = credentials.eq(&self.credential);
        let AuthorizeResult {
            credentials: c,
            result,
        } = result.authorize_sync(credentials);
        match result {
            Ok(maybe_ext) => {
                ext.insert(self.clone());
                if maybe_ext.is_none() {
                    return AuthorizeResult {
                        credentials: c,
                        result: Ok(Some(ext)),
                    };
                }
                AuthorizeResult {
                    credentials: c,
                    result: Ok(maybe_ext),
                }
            }
            Err(err) => AuthorizeResult {
                credentials: c,
                result: Err(err),
            },
        }
    }
}

impl<C, L, T> AuthoritySync<C, L> for UserCredInfo<T>
where
    C: Credentials + Send + 'static,
    T: AuthoritySync<C, L> + Clone,
{
    fn authorized(&self, ext: &mut Extensions, credentials: &C) -> bool {
        if self.credential.authorized(ext, credentials) {
            ext.insert(self.clone());
            true
        } else {
            false
        }
    }
}

/// Storage backend for user credentials.
pub enum UserCredStoreBackend<A> {
    /// Uses RwLock for thread-safe access with blocking updates.
    RwLock(Arc<RwLock<Vec<UserCredInfo<A>>>>),
    /// Uses ArcSwap for lock-free reads with atomic updates.
    ArcSwap(Arc<ArcSwapAny<Arc<Vec<UserCredInfo<A>>>>>),
    /// Uses ArcShift for efficient updates with shared access.
    ArcShift(ArcShift<Vec<UserCredInfo<A>>>),
}

impl<A> std::fmt::Debug for UserCredStoreBackend<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RwLock(_) => f.debug_tuple("RwLock").finish(),
            Self::ArcSwap(_) => f.debug_tuple("ArcSwap").finish(),
            Self::ArcShift(_) => f.debug_tuple("ArcShift").finish(),
        }
    }
}

impl<A> Clone for UserCredStoreBackend<A> {
    fn clone(&self) -> Self {
        match self {
            Self::RwLock(lock) => Self::RwLock(lock.clone()),
            Self::ArcSwap(swap) => Self::ArcSwap(swap.clone()),
            Self::ArcShift(shift) => Self::ArcShift(shift.clone()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct UserCredStore<A> {
    pub backend: UserCredStoreBackend<A>,
}

impl<A> UserCredStore<A> {
    /// Create a new store using RwLock backend.
    #[must_use]
    pub fn new(users: Vec<UserCredInfo<A>>) -> Self {
        Self {
            backend: UserCredStoreBackend::RwLock(Arc::new(RwLock::new(users))),
        }
    }

    /// Create a new store using ArcSwap backend for lock-free reads.
    #[must_use]
    pub fn new_arc_swap(users: Vec<UserCredInfo<A>>) -> Self {
        Self {
            backend: UserCredStoreBackend::ArcSwap(Arc::new(ArcSwap::from(Arc::new(users)))),
        }
    }

    /// Create a new store using ArcShift backend.
    #[must_use]
    pub fn new_arc_shift(users: Vec<UserCredInfo<A>>) -> Self {
        Self {
            backend: UserCredStoreBackend::ArcShift(ArcShift::new(users)),
        }
    }

    /// Try to update credentials without blocking (only works with RwLock backend).
    pub fn try_update(&self, users: Vec<UserCredInfo<A>>) -> Result<(), Vec<UserCredInfo<A>>> {
        match &self.backend {
            UserCredStoreBackend::RwLock(lock) => {
                if let Ok(mut guard) = lock.try_write() {
                    *guard = users;
                    tracing::trace!("User credentials updated successfully");
                    Ok(())
                } else {
                    tracing::trace!("Failed to acquire write lock for user credentials update");
                    Err(users)
                }
            }
            UserCredStoreBackend::ArcSwap(swap) => {
                swap.store(Arc::new(users));
                tracing::trace!("User credentials updated successfully");
                Ok(())
            }
            UserCredStoreBackend::ArcShift(_) => {
                tracing::trace!(
                    "try_update not supported for ArcShift backend, use update instead"
                );
                Err(users)
            }
        }
    }

    /// Update credentials (async for RwLock, sync for others).
    pub async fn update(&mut self, users: Vec<UserCredInfo<A>>) {
        match &mut self.backend {
            UserCredStoreBackend::RwLock(lock) => {
                let mut guard = lock.write().await;
                *guard = users;
                tracing::trace!("User credentials updated successfully");
            }
            UserCredStoreBackend::ArcSwap(swap) => {
                swap.store(Arc::new(users));
                tracing::trace!("User credentials updated successfully");
            }
            UserCredStoreBackend::ArcShift(shift) => {
                shift.update(users);
                shift.reload();
                tracing::trace!("User credentials updated successfully");
            }
        }
    }

    /// Update credentials synchronously (only works with ArcSwap and ArcShift backends).
    pub fn update_sync(&mut self, users: Vec<UserCredInfo<A>>) -> Result<(), Vec<UserCredInfo<A>>> {
        match &mut self.backend {
            UserCredStoreBackend::RwLock(_) => {
                tracing::trace!(
                    "Synchronous update not supported for RwLock backend, use update instead"
                );
                Err(users)
            }
            UserCredStoreBackend::ArcSwap(swap) => {
                swap.store(Arc::new(users));
                tracing::trace!("User credentials updated successfully");
                Ok(())
            }
            UserCredStoreBackend::ArcShift(shift) => {
                shift.update(users);
                shift.reload();
                tracing::trace!("User credentials updated successfully");
                Ok(())
            }
        }
    }
}

impl UserCredStore<Basic> {
    pub async fn get_user_cred_info(&self, username: &str) -> Option<UserCredInfo<Basic>> {
        match &self.backend {
            UserCredStoreBackend::RwLock(lock) => {
                let guard = lock.read().await;
                guard
                    .iter()
                    .find(|info| info.credential.username() == username)
                    .cloned()
            }
            UserCredStoreBackend::ArcSwap(swap) => {
                let guard = swap.load();
                guard
                    .iter()
                    .find(|info| info.credential.username() == username)
                    .cloned()
            }
            UserCredStoreBackend::ArcShift(shift) => {
                let guard = shift.shared_non_reloading_get();
                guard
                    .iter()
                    .find(|info| info.credential.username() == username)
                    .cloned()
            }
        }
    }
}

impl<C: PartialEq + Clone + Send + Sync + 'static> Authorizer<C> for UserCredStore<C> {
    type Error = Unauthorized;

    async fn authorize(&self, mut credentials: C) -> AuthorizeResult<C, Self::Error> {
        let mut error = None;

        match &self.backend {
            UserCredStoreBackend::RwLock(lock) => {
                let guard = lock.read().await;
                for authorizer in guard.iter() {
                    let AuthorizeResult {
                        credentials: c,
                        result,
                    } = authorizer.authorize_sync(credentials);
                    match result {
                        Ok(maybe_ext) => {
                            return AuthorizeResult {
                                credentials: c,
                                result: Ok(maybe_ext),
                            };
                        }
                        Err(err) => {
                            error = Some(err);
                            credentials = c;
                        }
                    }
                }
            }
            UserCredStoreBackend::ArcSwap(swap) => {
                let guard = swap.load();
                for authorizer in guard.iter() {
                    let AuthorizeResult {
                        credentials: c,
                        result,
                    } = authorizer.authorize_sync(credentials);
                    match result {
                        Ok(maybe_ext) => {
                            return AuthorizeResult {
                                credentials: c,
                                result: Ok(maybe_ext),
                            };
                        }
                        Err(err) => {
                            error = Some(err);
                            credentials = c;
                        }
                    }
                }
            }
            UserCredStoreBackend::ArcShift(shift) => {
                let guard = shift.shared_get();
                for authorizer in guard.iter() {
                    let AuthorizeResult {
                        credentials: c,
                        result,
                    } = authorizer.authorize_sync(credentials);
                    match result {
                        Ok(maybe_ext) => {
                            return AuthorizeResult {
                                credentials: c,
                                result: Ok(maybe_ext),
                            };
                        }
                        Err(err) => {
                            error = Some(err);
                            credentials = c;
                        }
                    }
                }
            }
        }
        AuthorizeResult {
            credentials,
            result: Err(error.unwrap()),
        }
    }
}

#[cfg(test)]
mod tests {
    use rama_http_types::header::HeaderMap;

    use super::super::{test_decode, test_encode};
    use super::{Authorization, Basic, Bearer};
    use crate::HeaderMapExt;

    #[test]
    fn basic_encode() {
        let auth = Authorization::new(Basic::new_static("Aladdin", "open sesame"));
        let headers = test_encode(auth);

        assert_eq!(
            headers["authorization"],
            "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
        );
    }

    #[test]
    fn basic_username_encode() {
        let auth = Authorization::new(Basic::new_static_insecure("Aladdin"));
        let headers = test_encode(auth);

        assert_eq!(headers["authorization"], "Basic QWxhZGRpbjo=",);
    }

    #[test]
    fn basic_roundtrip() {
        let auth = Authorization::new(Basic::new_static("Aladdin", "open sesame"));
        let mut h = HeaderMap::new();
        h.typed_insert(&auth);
        assert_eq!(h.typed_get(), Some(auth));
    }

    #[test]
    fn basic_decode() {
        let auth: Authorization<Basic> =
            test_decode(&["Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="]).unwrap();
        assert_eq!(auth.0.username(), "Aladdin");
        assert_eq!(auth.0.password(), "open sesame");
    }

    #[test]
    fn basic_decode_case_insensitive() {
        let auth: Authorization<Basic> =
            test_decode(&["basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="]).unwrap();
        assert_eq!(auth.0.username(), "Aladdin");
        assert_eq!(auth.0.password(), "open sesame");
    }

    #[test]
    fn basic_decode_extra_whitespaces() {
        let auth: Authorization<Basic> =
            test_decode(&["Basic  QWxhZGRpbjpvcGVuIHNlc2FtZQ=="]).unwrap();
        assert_eq!(auth.0.username(), "Aladdin");
        assert_eq!(auth.0.password(), "open sesame");
    }

    #[test]
    fn basic_decode_no_password() {
        let auth: Authorization<Basic> = test_decode(&["Basic QWxhZGRpbjo="]).unwrap();
        assert_eq!(auth.0.username(), "Aladdin");
        assert_eq!(auth.0.password(), "");
    }

    #[test]
    fn bearer_encode() {
        let auth = Authorization::new(Bearer::new_static("fpKL54jvWmEGVoRdCNjG"));

        let headers = test_encode(auth);

        assert_eq!(headers["authorization"], "Bearer fpKL54jvWmEGVoRdCNjG",);
    }

    #[test]
    fn bearer_decode() {
        let auth: Authorization<Bearer> = test_decode(&["Bearer fpKL54jvWmEGVoRdCNjG"]).unwrap();
        assert_eq!(auth.0.token().as_bytes(), b"fpKL54jvWmEGVoRdCNjG");
    }

    #[test]
    fn bearer_decode_case_insensitive() {
        let auth: Authorization<Bearer> = test_decode(&["bearer fpKL54jvWmEGVoRdCNjG"]).unwrap();
        assert_eq!(auth.0.token().as_bytes(), b"fpKL54jvWmEGVoRdCNjG");
    }

    #[test]
    fn bearer_decode_extra_whitespaces() {
        let auth: Authorization<Bearer> = test_decode(&["Bearer   fpKL54jvWmEGVoRdCNjG"]).unwrap();
        assert_eq!(auth.0.token().as_bytes(), b"fpKL54jvWmEGVoRdCNjG");
    }
}

//bench_header!(raw, Authorization<String>, { vec![b"foo bar baz".to_vec()] });
//bench_header!(basic, Authorization<Basic>, { vec![b"Basic QWxhZGRpbjpuIHNlc2FtZQ==".to_vec()] });
//bench_header!(bearer, Authorization<Bearer>, { vec![b"Bearer fpKL54jvWmEGVoRdCNjG".to_vec()] });

#[cfg(test)]
mod test_auth {
    use super::*;
    use rama_core::username::{UsernameLabels, UsernameOpaqueLabelParser};

    #[tokio::test]
    async fn basic_authorization() {
        let auth = Basic::new_static("Aladdin", "open sesame");
        let auths = vec![Basic::new_static("foo", "bar"), auth.clone()];
        let ext = Authority::<_, ()>::authorized(&auths, auth).await.unwrap();
        let user: &UserId = ext.get().unwrap();
        assert_eq!(user, "Aladdin");
    }

    #[tokio::test]
    async fn basic_authorization_with_labels_found() {
        let auths = vec![
            Basic::new_static("foo", "bar"),
            Basic::new_static("john", "secret"),
        ];

        let ext = Authority::<_, UsernameOpaqueLabelParser>::authorized(
            &auths,
            Basic::new_static("john-green-red", "secret"),
        )
        .await
        .unwrap();

        let c: &UserId = ext.get().unwrap();
        assert_eq!(c, "john");

        let labels: &UsernameLabels = ext.get().unwrap();
        assert_eq!(&labels.0, &vec!["green".to_owned(), "red".to_owned()]);
    }

    #[tokio::test]
    async fn basic_authorization_with_labels_not_found() {
        let auth = Basic::new_static("john", "secret");
        let auths = vec![Basic::new_static("foo", "bar"), auth.clone()];

        let ext = Authority::<_, UsernameOpaqueLabelParser>::authorized(&auths, auth)
            .await
            .unwrap();

        let c: &UserId = ext.get().unwrap();
        assert_eq!(c, "john");

        assert!(ext.get::<UsernameLabels>().is_none());
    }
}
