//! Middleware that validates if a request has the appropriate Proxy Authorisation.
//!
//! If the request is not authorized a `407 Proxy Authentication Required` response will be sent.

use crate::header::PROXY_AUTHENTICATE;
use crate::headers::authorization::Authority;
use crate::headers::{HeaderMapExt, ProxyAuthorization, authorization::Credentials};
use crate::{Request, Response, StatusCode};
use rama_core::{Context, Layer, Service};
use rama_http_headers::authorization::{AuthoritySync, UserCredStore};
use rama_net::user::UserId;
use rama_utils::macros::define_inner_service_accessors;
use std::fmt;
use std::marker::PhantomData;

/// Layer that applies the [`ProxyAuthService`] middleware which apply a timeout to requests.
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
    /// Creates a new [`CustomProxyAuthLayer`].
    pub const fn new(proxy_auth: UserCredStore<A>) -> Self {
        CustomProxyAuthLayer {
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
    }

    fn into_layer(self, inner: S) -> Self::Service {
        CustomProxyAuthService::new(self.proxy_auth, inner)
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
        CustomProxyAuthService {
            proxy_auth: self.proxy_auth.clone(),
            allow_anonymous: self.allow_anonymous,
            inner: self.inner.clone(),
            _phantom: PhantomData,
        }
    }
}

impl<A, C, L, S, State, ReqBody, ResBody> Service<State, Request<ReqBody>>
    for CustomProxyAuthService<A, C, S, L>
where
    // A: Authority<C, L>,
    A: Authority<C, L> + AuthoritySync<C, L> + Clone,
    C: Credentials + Clone + Send + Sync + 'static,
    S: Service<State, Request<ReqBody>, Response = Response<ResBody>>,
    L: 'static,
    ReqBody: Send + 'static,
    ResBody: Default + Send + 'static,
    State: Clone + Send + Sync + 'static,
{
    type Response = S::Response;
    type Error = S::Error;

    async fn serve(
        &self,
        mut ctx: Context<State>,
        req: Request<ReqBody>,
    ) -> Result<Self::Response, Self::Error> {
        if let Some(credentials) = req
            .headers()
            .typed_get::<ProxyAuthorization<C>>()
            .map(|h| h.0)
            .or_else(|| ctx.get::<C>().cloned())
        {
            if let Some(ext) = {
                let data_guard = self.proxy_auth.0.read().await;
                Authority::<C, L>::authorized(&*data_guard, credentials).await
            } {
                ctx.extend(ext);
                self.inner.serve(ctx, req).await
            } else {
                Ok(Response::builder()
                    .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                    .header(PROXY_AUTHENTICATE, C::SCHEME)
                    .body(Default::default())
                    .unwrap())
            }
        } else if self.allow_anonymous {
            ctx.insert(UserId::Anonymous);
            self.inner.serve(ctx, req).await
        } else {
            Ok(Response::builder()
                .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                .header(PROXY_AUTHENTICATE, C::SCHEME)
                .body(Default::default())
                .unwrap())
        }
    }
}
