//! Middleware that validates if a request has the appropriate Proxy Authorisation.
//!
//! If the request is not authorized a `407 Proxy Authentication Required` response will be sent.

use crate::header::PROXY_AUTHENTICATE;
use crate::headers::authorization::Authority;
use crate::headers::{HeaderMapExt, ProxyAuthorization, authorization::Credentials};
use crate::{Request, Response, StatusCode};
use rama_core::context::Extensions;
use rama_core::telemetry::tracing;
use rama_core::{Context, Layer, Service};
use rama_http_headers::authorization::{AuthoritySync, UserCredStore, UserCredStoreBackend};
use rama_net::user::UserId;
use rama_utils::macros::define_inner_service_accessors;
use std::fmt;
use std::marker::PhantomData;

/// Layer that applies the [`CustomProxyAuthService`] middleware which apply a timeout to requests.
///
/// See the [module docs](super) for an example.
pub struct CustomProxyAuthLayer<A, C, L = ()> {
    proxy_auth: UserCredStore<A>,
    allow_anonymous: bool,
    _phantom: PhantomData<fn(C, L) -> ()>,
}

impl<A: fmt::Debug, C, L> fmt::Debug for CustomProxyAuthLayer<A, C, L> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("CustomProxyAuthLayer")
            .field("proxy_auth", &self.proxy_auth)
            .field("allow_anonymous", &self.allow_anonymous)
            .field(
                "_phantom",
                &format_args!("{}", std::any::type_name::<fn(C, L) -> ()>()),
            )
            .finish()
    }
}

impl<A: Clone, C, L> Clone for CustomProxyAuthLayer<A, C, L> {
    fn clone(&self) -> Self {
        Self {
            proxy_auth: self.proxy_auth.clone(),
            allow_anonymous: self.allow_anonymous,
            _phantom: PhantomData,
        }
    }
}

impl<A, C> CustomProxyAuthLayer<A, C, ()> {
    /// Creates a new [`CustomProxyAuthLayer`] with UserCredStore.
    #[must_use]
    pub const fn new(proxy_auth: UserCredStore<A>) -> Self {
        Self {
            proxy_auth,
            allow_anonymous: false,
            _phantom: PhantomData,
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

impl<A, C, L> CustomProxyAuthLayer<A, C, L> {
    /// Overwrite the Labels extract type
    ///
    /// This is used if the username contains labels that you need to extract out.
    /// Example implementation is the [`UsernameOpaqueLabelParser`].
    ///
    /// You can provide your own extractor by implementing the [`UsernameLabelParser`] trait.
    ///
    /// [`UsernameOpaqueLabelParser`]: rama_core::username::UsernameOpaqueLabelParser
    /// [`UsernameLabelParser`]: rama_core::username::UsernameLabelParser
    #[must_use]
    pub fn with_labels<L2>(self) -> CustomProxyAuthLayer<A, C, L2> {
        CustomProxyAuthLayer {
            proxy_auth: self.proxy_auth,
            allow_anonymous: self.allow_anonymous,
            _phantom: PhantomData,
        }
    }
}

impl<A, C, L, S> Layer<S> for CustomProxyAuthLayer<A, C, L>
where
    A: Authority<C, L> + Clone,
    C: Credentials + Clone + Send + Sync + 'static,
{
    type Service = CustomProxyAuthService<A, C, S, L>;

    fn layer(&self, inner: S) -> Self::Service {
        CustomProxyAuthService::new(self.proxy_auth.clone(), inner)
            .with_allow_anonymous(self.allow_anonymous)
    }

    fn into_layer(self, inner: S) -> Self::Service {
        CustomProxyAuthService::new(self.proxy_auth, inner)
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
pub struct CustomProxyAuthService<A, C, S, L = ()> {
    proxy_auth: UserCredStore<A>,
    allow_anonymous: bool,
    inner: S,
    _phantom: PhantomData<fn(C, L) -> ()>,
}

impl<A, C, S, L> CustomProxyAuthService<A, C, S, L> {
    /// Creates a new [`CustomProxyAuthService`].
    #[must_use]
    pub const fn new(proxy_auth: UserCredStore<A>, inner: S) -> Self {
        Self {
            proxy_auth,
            allow_anonymous: false,
            inner,
            _phantom: PhantomData,
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

impl<A: fmt::Debug, C, S: fmt::Debug, L> fmt::Debug for CustomProxyAuthService<A, C, S, L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CustomProxyAuthService")
            .field("proxy_auth", &self.proxy_auth)
            .field("allow_anonymous", &self.allow_anonymous)
            .field("inner", &self.inner)
            .field(
                "_phantom",
                &format_args!("{}", std::any::type_name::<fn(C, L) -> ()>()),
            )
            .finish()
    }
}

impl<A: Clone, C, S: Clone, L> Clone for CustomProxyAuthService<A, C, S, L> {
    fn clone(&self) -> Self {
        Self {
            proxy_auth: self.proxy_auth.clone(),
            allow_anonymous: self.allow_anonymous,
            inner: self.inner.clone(),
            _phantom: PhantomData,
        }
    }
}

#[inline]
fn create_auth_required_response<ResBody: Default>(scheme: &'static str) -> Response<ResBody> {
    Response::builder()
        .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
        .header(PROXY_AUTHENTICATE, scheme)
        .body(Default::default())
        .unwrap()
}

impl<A, C, L, S, ReqBody, ResBody> Service<Request<ReqBody>> for CustomProxyAuthService<A, C, S, L>
where
    A: Authority<C, L> + AuthoritySync<C, L> + Clone,
    C: Credentials + Clone + Send + Sync + 'static,
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    L: 'static,
    ReqBody: Send + 'static,
    ResBody: Default + Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;

    async fn serve(
        &self,
        mut ctx: Context,
        req: Request<ReqBody>,
    ) -> Result<Self::Response, Self::Error> {
        let credentials = req
            .headers()
            .typed_get::<ProxyAuthorization<C>>()
            .map(|h| h.0)
            .or_else(|| ctx.get::<C>().cloned());

        match credentials {
            Some(creds) => {
                tracing::trace!("Proxy credentials found");
                let auth_result = match &self.proxy_auth.backend {
                    UserCredStoreBackend::RwLock(store) => {
                        let data_guard = store.read().await;
                        Authority::<C, L>::authorized(&*data_guard, creds).await
                    }
                    UserCredStoreBackend::ArcSwap(store) => {
                        let data_guard = store.load();
                        Authority::<C, L>::authorized(&*data_guard, creds).await
                    }
                    UserCredStoreBackend::ArcShift(store) => {
                        let data_guard = store.shared_get();
                        let mut ext = Extensions::new();
                        if data_guard.iter().any(|user_cred_info| {
                            AuthoritySync::<C, L>::authorized(user_cred_info, &mut ext, &creds)
                        }) {
                            Some(ext)
                        } else {
                            None
                        }
                    }
                };

                tracing::trace!(
                    auth_result = ?auth_result,
                    "Proxy credentials checked"
                );

                match auth_result {
                    Some(ext) => {
                        ctx.extend(ext);
                        self.inner.serve(ctx, req).await
                    }
                    None => Ok(create_auth_required_response(C::SCHEME)),
                }
            }
            None => {
                if self.allow_anonymous {
                    ctx.insert(UserId::Anonymous);
                    self.inner.serve(ctx, req).await
                } else {
                    Ok(create_auth_required_response(C::SCHEME))
                }
            }
        }
    }
}
