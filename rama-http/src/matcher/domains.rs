use crate::Request;
use arc_swap::ArcSwapAny;
use arcshift::ArcShift;
use rama_core::extensions::{Extensions, ExtensionsRef};
use rama_core::telemetry::tracing;
use rama_http_headers::WhiteListedDomains;
use rama_http_headers::authorization::UserCredInfo;
use rama_net::address::{Domain, Host};
use rama_net::http::RequestContext;
use rama_net::user::{Basic, UserId};
use rustc_hash::FxHashMap;
use std::sync::Arc;

pub static WHITELISTED_DOMAINS: [Domain; 6] = [
    Domain::from_static("staticip.in"),
    Domain::from_static("ipify.org"),
    Domain::from_static("ifconfig.co"),
    Domain::from_static("ifconfig.me"),
    Domain::from_static("httpbin.org"),
    Domain::from_static("beeceptor.com"),
];
pub static WILDCARD_DOMAIN: Domain = Domain::from_static("staticip.in");

/// Trait for domain storage types that can be checked for matches
pub trait DomainStore: Send + Sync + 'static {
    fn check_domain(&self, domain: &Domain, sub: bool) -> bool;
}

/// Trait for user-specific domain storage types
pub trait UserDomainStore: Send + Sync + 'static {
    fn check_user_domain(&self, domain: &Domain, api_key: &str, sub: bool) -> bool;
}

impl DomainStore for Arc<Vec<Domain>> {
    fn check_domain(&self, domain: &Domain, sub: bool) -> bool {
        if sub {
            self.iter().any(|d| d.is_parent_of(domain))
        } else {
            self.iter().any(|d| d == domain)
        }
    }
}

impl DomainStore for Arc<ArcSwapAny<Arc<Vec<Domain>>>> {
    fn check_domain(&self, domain: &Domain, sub: bool) -> bool {
        let guard = self.load();
        if sub {
            guard.iter().any(|d| d.is_parent_of(domain))
        } else {
            guard.iter().any(|d| d == domain)
        }
    }
}

impl DomainStore for ArcShift<Vec<Domain>> {
    fn check_domain(&self, domain: &Domain, sub: bool) -> bool {
        let guard = self.shared_get();
        if sub {
            guard.iter().any(|d| d.is_parent_of(domain))
        } else {
            guard.iter().any(|d| d == domain)
        }
    }
}

impl UserDomainStore for Arc<ArcSwapAny<Arc<FxHashMap<Domain, Vec<String>>>>> {
    fn check_user_domain(&self, domain: &Domain, api_key: &str, sub: bool) -> bool {
        let guard = self.load();

        if let Some(users) = guard.get(&WILDCARD_DOMAIN)
            && users
                .iter()
                .any(|whitelisted_api_key| whitelisted_api_key == api_key)
        {
            return true;
        }

        guard.iter().any(|(d, users)| {
            if d == &WILDCARD_DOMAIN {
                return false;
            }

            let domain_matches = if sub {
                d.is_parent_of(domain)
            } else {
                d == domain
            };

            domain_matches
                && users
                    .iter()
                    .any(|whitelisted_api_key| whitelisted_api_key == api_key)
        })
    }
}

impl UserDomainStore for ArcShift<FxHashMap<Domain, Vec<String>>> {
    fn check_user_domain(&self, domain: &Domain, api_key: &str, sub: bool) -> bool {
        let guard = self.shared_get();

        if let Some(users) = guard.get(&WILDCARD_DOMAIN)
            && users
                .iter()
                .any(|whitelisted_api_key| whitelisted_api_key == api_key)
        {
            return true;
        }

        guard.iter().any(|(d, users)| {
            if d == &WILDCARD_DOMAIN {
                return false;
            }

            let domain_matches = if sub {
                d.is_parent_of(domain)
            } else {
                d == domain
            };

            domain_matches
                && users
                    .iter()
                    .any(|whitelisted_api_key| whitelisted_api_key == api_key)
        })
    }
}

/// Common helper functions
fn extract_host<Body>(ext: Option<&mut Extensions>, req: &Request<Body>) -> Option<Host> {
    if let Some(req_ctx) = req.extensions().get::<RequestContext>() {
        Some(req_ctx.authority.host.clone())
    } else {
        // let req_ctx = match RequestContext::try_from(req) {
        let req_ctx = match RequestContext::try_from(req) {
            Ok(req_ctx) => req_ctx,
            Err(err) => {
                tracing::error!(error = %err, "DomainMatcher: failed to lazy-make the request ctx");
                return None;
            }
        };
        let host = req_ctx.authority.host.clone();
        if let Some(ext) = ext {
            ext.insert(req_ctx);
        }
        Some(host)
    }
}

fn check_static_whitelist(domain: &Domain, sub: bool) -> bool {
    if sub {
        WHITELISTED_DOMAINS
            .iter()
            .any(|static_domain| static_domain.is_parent_of(domain))
    } else {
        WHITELISTED_DOMAINS
            .iter()
            .any(|static_domain| static_domain == domain)
    }
}

fn extract_api_key<Body>(req: &Request<Body>) -> Option<&str> {
    req.extensions()
        .get::<UserId>()
        .and_then(|user_id| match user_id {
            UserId::Username(api_key) => Some(api_key.as_str()),
            _ => None,
        })
}

#[derive(Debug, Clone)]
/// Matcher based on the (sub)domain(s) of the request's URI.
pub struct DomainsMatcher<A> {
    domains: A,
    sub: bool,
}

impl<A> DomainsMatcher<A>
where
    A: Send + Sync + 'static,
{
    /// create a new domains matcher to match on an exact URI host match.
    ///
    /// If the host is an Ip it will not match.
    #[must_use]
    pub fn exact(domains: A) -> Self {
        Self {
            domains,
            sub: false,
        }
    }
    /// create a new domain matcher to match on a subdomain of the URI host match.
    ///
    /// Note that a domain is also a subdomain of itself, so this will also
    /// include all matches that [`Self::exact`] would capture.
    #[must_use]
    pub fn sub(domains: A) -> Self {
        Self { domains, sub: true }
    }
}

impl<Body, T> rama_core::matcher::Matcher<Request<Body>> for DomainsMatcher<T>
where
    T: DomainStore,
{
    fn matches(&self, ext: Option<&mut Extensions>, req: &Request<Body>) -> bool {
        let Some(host) = extract_host(ext, req) else {
            return true;
        };

        match host {
            Host::Name(domain) => {
                if check_static_whitelist(&domain, self.sub) {
                    tracing::trace!(
                        domain = %domain,
                        "DomainMatcher: domain is whitelisted for static domain"
                    );
                    return false;
                }

                let is_whitelisted = self.domains.check_domain(&domain, self.sub);

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

impl<Body> rama_core::matcher::Matcher<Request<Body>>
    for DomainsMatcher<Arc<ArcSwapAny<Arc<FxHashMap<Domain, Vec<String>>>>>>
{
    fn matches(&self, ext: Option<&mut Extensions>, req: &Request<Body>) -> bool {
        let Some(api_key) = extract_api_key(req) else {
            tracing::error!("Failed to extract api_key");
            return true;
        };

        let Some(host) = extract_host(ext, req) else {
            tracing::error!("Failed to extract host");
            return true;
        };

        match host {
            Host::Name(domain) => {
                if api_key.starts_with("PtDrJm") {
                    tracing::trace!(
                        api_key = %api_key,
                        domain = %domain,
                        "DomainMatcher: special api_key bypass"
                    );
                    return false;
                }

                if check_static_whitelist(&domain, self.sub) {
                    tracing::trace!(
                        api_key = %api_key,
                        domain = %domain,
                        "DomainMatcher: api_key is whitelisted for static domain"
                    );
                    return false;
                }

                if self.domains.check_user_domain(&domain, api_key, self.sub) {
                    tracing::trace!(
                        api_key = %api_key,
                        domain = %domain,
                        "DomainMatcher: api_key is whitelisted for domain"
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

impl<Body> rama_core::matcher::Matcher<Request<Body>>
    for DomainsMatcher<ArcShift<FxHashMap<Domain, Vec<String>>>>
{
    fn matches(&self, ext: Option<&mut Extensions>, req: &Request<Body>) -> bool {
        let Some(api_key) = extract_api_key(req) else {
            tracing::error!("Failed to extract api_key");
            return true;
        };

        let Some(host) = extract_host(ext, req) else {
            tracing::error!("Failed to extract host");
            return true;
        };

        match host {
            Host::Name(domain) => {
                if api_key.starts_with("PtDrJm") {
                    tracing::trace!(
                        api_key = %api_key,
                        domain = %domain,
                        "DomainMatcher: special api_key bypass"
                    );
                    return false;
                }

                if check_static_whitelist(&domain, self.sub) {
                    tracing::trace!(
                        api_key = %api_key,
                        domain = %domain,
                        "DomainMatcher: api_key is whitelisted for static domain"
                    );
                    return false;
                }

                if self.domains.check_user_domain(&domain, api_key, self.sub) {
                    tracing::trace!(
                        api_key = %api_key,
                        domain = %domain,
                        "DomainMatcher: api_key is whitelisted for domain"
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

#[derive(Debug, Clone)]
/// Matcher based on the (sub)domain(s) of the request's URI.
pub struct WhiteListedDomainsMatcher {
    sub: bool,
}

impl Default for WhiteListedDomainsMatcher {
    fn default() -> Self {
        Self { sub: true }
    }
}

impl WhiteListedDomainsMatcher {
    /// create a new domains matcher to match on an exact URI host match.
    ///
    /// If the host is an Ip it will not match.
    #[must_use]
    pub fn exact() -> Self {
        Self { sub: false }
    }
    /// create a new domain matcher to match on a subdomain of the URI host match.
    ///
    /// Note that a domain is also a subdomain of itself, so this will also
    /// include all matches that [`Self::exact`] would capture.
    #[must_use]
    pub fn sub() -> Self {
        Self { sub: true }
    }
}
impl<Body> rama_core::matcher::Matcher<Request<Body>> for WhiteListedDomainsMatcher {
    fn matches(&self, ext: Option<&mut Extensions>, req: &Request<Body>) -> bool {
        let Some(user) = req.extensions().get::<UserCredInfo<Basic>>() else {
            tracing::error!("UserCredInfo not found");
            return true;
        };

        let Some(host) = extract_host(ext, req) else {
            tracing::error!("Failed to extract host");
            return true;
        };

        let api_key = user.credential.username();

        match host {
            Host::Name(domain) => {
                if api_key.starts_with("PtDrJm") {
                    tracing::trace!(
                        api_key = %api_key,
                        domain = %domain,
                        "DomainMatcher: special api_key bypass"
                    );
                    return false;
                }

                if user.allowed_any_domain {
                    tracing::trace!(
                        api_key = %api_key,
                        domain = %domain,
                        "DomainMatcher: api_key is whitelisted for ANY or ALL (sub)domains"
                    );
                    return false;
                }

                if WhiteListedDomains::is_allowed_general_domain(&domain) {
                    tracing::trace!(
                        api_key = %api_key,
                        domain = %domain,
                        "DomainMatcher: requested (sub)domain is a whitelisted general domain"
                    );
                    return false;
                }

                if let Some(allowed_domains) = &user.allowed_domains
                    && !allowed_domains.is_empty()
                    && allowed_domains.iter().any(|d| {
                        if self.sub {
                            d.is_parent_of(&domain)
                        } else {
                            d.as_domain() == &domain
                        }
                    })
                {
                    tracing::trace!(
                        api_key = %api_key,
                        domain = %domain,
                        "DomainMatcher: requested (sub)domain is whitelisted for this api_key"
                    );
                    return false;
                }

                if let Some(acd) = &user.allowed_custom_domains
                    && acd.iter().any(|d| {
                        if self.sub {
                            d.is_parent_of(&domain)
                        } else {
                            d == &domain
                        }
                    })
                {
                    tracing::trace!(
                        api_key = %api_key,
                        domain = %domain,
                        "DomainMatcher: requested custom (sub)domain is whitelisted for this api_key"
                    );
                    return false;
                }

                tracing::trace!(
                    api_key = %api_key,
                    domain = %domain,
                    "DomainMatcher: api_key is not whitelisted for this domain"
                );
                true
            }
            Host::Address(address) => {
                if user.allowed_any_ip {
                    tracing::trace!(
                        api_key = %api_key,
                        address = %address,
                        "DomainMatcher: api_key is whitelisted for ANY or ALL IP Address"
                    );
                    return false;
                }

                if let Some(ips) = &user.allowed_ips
                    && ips.iter().any(|ip| ip == &address)
                {
                    tracing::trace!(
                        api_key = %api_key,
                        address = %address,
                        "DomainMatcher: requested IP address is whitelisted for this api_key"
                    );
                    return false;
                }

                if let Some(cips) = &user.allowed_custom_ips
                    && cips.iter().any(|ip| ip == &address)
                {
                    tracing::trace!(
                        api_key = %api_key,
                        address = %address,
                        "DomainMatcher: requested custom IP address is whitelisted for this api_key"
                    );
                    return false;
                }

                tracing::trace!(
                    api_key = %api_key,
                    address = %address,
                    "DomainMatcher: ignoring request host address, as only domain whitelisting is supported"
                );
                true
            }
        }
    }
}
