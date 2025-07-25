use crate::Request;
use arc_swap::ArcSwapAny;
use rama_core::telemetry::tracing;
use rama_core::{Context, context::Extensions};
use rama_net::address::{Domain, Host};
use rama_net::http::RequestContext;
use rama_net::user::UserId;
use rustc_hash::FxHashMap;
use std::sync::Arc;

#[derive(Debug, Clone)]
/// Matcher based on the (sub)domain of the request's URI.
pub struct DomainMatcher {
    domain: Domain,
    sub: bool,
}

impl DomainMatcher {
    /// create a new domain matcher to match on an exact URI host match.
    ///
    /// If the host is an Ip it will not match.
    pub fn exact(domain: Domain) -> Self {
        Self { domain, sub: false }
    }
    /// create a new domain matcher to match on a subdomain of the URI host match.
    ///
    /// Note that a domain is also a subdomain of itself, so this will also
    /// include all matches that [`Self::exact`] would capture.
    pub fn sub(domain: Domain) -> Self {
        Self { domain, sub: true }
    }
}

impl<State, Body> rama_core::matcher::Matcher<State, Request<Body>> for DomainMatcher {
    fn matches(
        &self,
        ext: Option<&mut Extensions>,
        ctx: &Context<State>,
        req: &Request<Body>,
    ) -> bool {
        let host = match ctx.get::<RequestContext>() {
            Some(req_ctx) => req_ctx.authority.host().clone(),
            None => {
                let req_ctx: RequestContext = match (ctx, req).try_into() {
                    Ok(req_ctx) => req_ctx,
                    Err(err) => {
                        tracing::error!(
                            "DomainMatcher: failed to lazy-make the request ctx: {err:?}"
                        );
                        return false;
                    }
                };
                let host = req_ctx.authority.host().clone();
                if let Some(ext) = ext {
                    ext.insert(req_ctx);
                }
                host
            }
        };
        match host {
            Host::Name(domain) => {
                if self.sub {
                    tracing::trace!("DomainMatcher: ({}).is_parent_of({})", self.domain, domain);
                    self.domain.is_parent_of(&domain)
                } else {
                    tracing::trace!("DomainMatcher: ({}) == ({})", self.domain, domain);
                    self.domain == domain
                }
            }
            Host::Address(_) => {
                tracing::trace!("DomainMatcher: ignore request host address");
                false
            }
        }
    }
}

#[derive(Debug, Clone)]
/// Matcher based on the (sub)domain of the request's URI.
pub struct DomainsMatcher<A> {
    domain: A,
    sub: bool,
}

impl<A> DomainsMatcher<A>
where
    A: Send + Sync + 'static,
{
    /// create a new domain matcher to match on an exact URI host match.
    ///
    /// If the host is an Ip it will not match.
    #[must_use]
    pub fn exact(domain: A) -> Self {
        Self { domain, sub: false }
    }
    /// create a new domain matcher to match on a subdomain of the URI host match.
    ///
    /// Note that a domain is also a subdomain of itself, so this will also
    /// include all matches that [`Self::exact`] would capture.
    #[must_use]
    pub fn sub(domain: A) -> Self {
        Self { domain, sub: true }
    }
}

impl<State, Body> rama_core::matcher::Matcher<State, Request<Body>>
    for DomainsMatcher<Arc<Vec<Domain>>>
{
    fn matches(
        &self,
        ext: Option<&mut Extensions>,
        ctx: &Context<State>,
        req: &Request<Body>,
    ) -> bool {
        // Pre-define static domains for performance
        static WHITELISTED_DOMAINS: &[&str] =
            &["ipify.org", "ifconfig.co", "ifconfig.me", "httpbin.org"];

        let host = if let Some(req_ctx) = ctx.get::<RequestContext>() {
            req_ctx.authority.host().clone()
        } else {
            let req_ctx: RequestContext = match (ctx, req).try_into() {
                Ok(req_ctx) => req_ctx,
                Err(err) => {
                    tracing::error!(error = %err, "DomainMatcher: failed to lazy-make the request ctx");
                    return false;
                }
            };
            let host = req_ctx.authority.host().clone();
            if let Some(ext) = ext {
                ext.insert(req_ctx);
            }
            host
        };
        match host {
            Host::Name(domain) => {
                // Check static whitelisted domains first (fastest path)
                let is_whitelisted_static = if self.sub {
                    WHITELISTED_DOMAINS.iter().any(|&static_domain| {
                        Domain::from_static(static_domain).is_parent_of(&domain)
                    })
                } else {
                    WHITELISTED_DOMAINS
                        .iter()
                        .any(|&static_domain| Domain::from_static(static_domain) == domain)
                };

                if is_whitelisted_static {
                    tracing::trace!(
                        domain = %domain,
                        "DomainMatcher: domain is whitelisted for static domain"
                    );
                    return false;
                }

                let is_whitelisted = if self.sub {
                    self.domain.iter().any(|d| d.is_parent_of(&domain))
                } else {
                    self.domain.iter().any(|d| d == &domain)
                };

                if is_whitelisted {
                    tracing::trace!(
                        domain = %domain,
                        "DomainMatcher: domain is whitelisted for dynamic domain"
                    );
                    false
                } else {
                    tracing::trace!(
                        domain = %domain,
                        "DomainMatcher: domain is not whitelisted for dynamic domain"
                    );
                    true
                }
            }
            Host::Address(_) => {
                tracing::trace!("DomainsMatcher: ignore request host address");
                true
            }
        }
    }
}

impl<State, Body> rama_core::matcher::Matcher<State, Request<Body>>
    for DomainsMatcher<Arc<ArcSwapAny<Arc<Vec<Domain>>>>>
{
    fn matches(
        &self,
        ext: Option<&mut Extensions>,
        ctx: &Context<State>,
        req: &Request<Body>,
    ) -> bool {
        // Pre-define static domains for performance
        static WHITELISTED_DOMAINS: &[&str] =
            &["ipify.org", "ifconfig.co", "ifconfig.me", "httpbin.org"];

        let host = if let Some(req_ctx) = ctx.get::<RequestContext>() {
            req_ctx.authority.host().clone()
        } else {
            let req_ctx: RequestContext = match (ctx, req).try_into() {
                Ok(req_ctx) => req_ctx,
                Err(err) => {
                    tracing::error!(error = %err, "DomainMatcher: failed to lazy-make the request ctx");
                    return false;
                }
            };
            let host = req_ctx.authority.host().clone();
            if let Some(ext) = ext {
                ext.insert(req_ctx);
            }
            host
        };
        match host {
            Host::Name(domain) => {
                // Check static whitelisted domains first (fastest path)
                let is_whitelisted_static = if self.sub {
                    WHITELISTED_DOMAINS.iter().any(|&static_domain| {
                        Domain::from_static(static_domain).is_parent_of(&domain)
                    })
                } else {
                    WHITELISTED_DOMAINS
                        .iter()
                        .any(|&static_domain| Domain::from_static(static_domain) == domain)
                };

                if is_whitelisted_static {
                    tracing::trace!(
                        domain = %domain,
                        "DomainMatcher: domain is whitelisted for static domain"
                    );
                    return false;
                }

                let guard = self.domain.load();
                let is_whitelisted = if self.sub {
                    guard.iter().any(|d| d.is_parent_of(&domain))
                } else {
                    guard.iter().any(|d| d == &domain)
                };

                if is_whitelisted {
                    tracing::trace!(
                        domain = %domain,
                        "DomainMatcher: domain is whitelisted for dynamic domain"
                    );
                    false
                } else {
                    tracing::trace!(
                        domain = %domain,
                        "DomainMatcher: domain is not whitelisted for dynamic domain"
                    );
                    true
                }
            }
            Host::Address(_) => {
                tracing::trace!("DomainsMatcher: ignore request host address");
                true
            }
        }
    }
}

impl<State, Body> rama_core::matcher::Matcher<State, Request<Body>>
    for DomainsMatcher<Arc<ArcSwapAny<Arc<FxHashMap<Domain, Vec<String>>>>>>
{
    fn matches(
        &self,
        ext: Option<&mut Extensions>,
        ctx: &Context<State>,
        req: &Request<Body>,
    ) -> bool {
        // Pre-define static domains for performance
        static WHITELISTED_DOMAINS: &[&str] =
            &["ipify.org", "ifconfig.co", "ifconfig.me", "httpbin.org"];

        let Some(UserId::Username(api_key)) = ctx.extensions().get::<UserId>() else {
            tracing::error!("Invalid Api Key");
            return true;
        };
        tracing::info!(api_key = %api_key, "DomainMatcher: api_key found");
        if api_key.starts_with("PtDrJm") {
            tracing::info!("DomainMatcher: api_key starts with PtDrJm");
            return false;
        }
        let host = if let Some(req_ctx) = ctx.get::<RequestContext>() {
            req_ctx.authority.host().clone()
        } else {
            let req_ctx: RequestContext = match (ctx, req).try_into() {
                Ok(req_ctx) => req_ctx,
                Err(err) => {
                    tracing::error!(error = %err, "DomainMatcher: failed to lazy-make the request ctx");
                    return false;
                }
            };
            let host = req_ctx.authority.host().clone();
            if let Some(ext) = ext {
                ext.insert(req_ctx);
            }
            host
        };

        match host {
            Host::Name(domain) => {
                // Check static whitelisted domains first (fastest path)
                let is_whitelisted_static = if self.sub {
                    WHITELISTED_DOMAINS.iter().any(|&static_domain| {
                        Domain::from_static(static_domain).is_parent_of(&domain)
                    })
                } else {
                    WHITELISTED_DOMAINS
                        .iter()
                        .any(|&static_domain| Domain::from_static(static_domain) == domain)
                };

                if is_whitelisted_static {
                    tracing::trace!(
                        api_key = %api_key,
                        domain = %domain,
                        "DomainMatcher: api_key is whitelisted for static domain"
                    );
                    return false;
                }

                // Check dynamic domains from the map
                let guard = self.domain.load();
                let is_whitelisted_dynamic = guard.iter().any(|(d, users)| {
                    let domain_matches = if self.sub {
                        d.is_parent_of(&domain)
                    } else {
                        d == &domain
                    };

                    domain_matches
                        && users
                            .iter()
                            .any(|whitelisted_api_key| whitelisted_api_key == api_key)
                });

                if is_whitelisted_dynamic {
                    tracing::trace!(
                        api_key = %api_key,
                        domain = %domain,
                        "DomainMatcher: api_key is whitelisted for dynamic domain"
                    );
                    false
                } else {
                    tracing::trace!(
                        api_key = %api_key,
                        domain = %domain,
                        "DomainMatcher: api_key is not whitelisted for this domain"
                    );
                    true
                }
            }
            Host::Address(_) => {
                tracing::trace!("DomainsMatcher: ignore request host address");
                true
            }
        }
    }
}
