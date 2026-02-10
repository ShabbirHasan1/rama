//! Socks5 Server Implementation for Rama.
//!
//! See [`Socks5Acceptor`] for more information,
//! its [`Default`] implementation only
//! supports the [`Command::Connect`] method using the [`DefaultConnector`],
//! but custom connectors as well as binders and udp associators
//! are optionally possible.
//!
//! For MITM socks5 proxies you can use [`LazyConnector`] as the
//! connector service of [`Socks5Acceptor`].

use crate::{
    proto::{
        Command, ReplyKind, SocksMethod, client,
        server::{Header, Reply, UsernamePasswordResponse},
    },
    server::{DefaultConnector, Error, connect::Socks5ConnectorSeal as _},
};
use rama_core::{
    Service,
    error::{BoxError, ErrorContext as _, ErrorExt as _},
    extensions::{Extensions, ExtensionsMut},
    rt::Executor,
    stream::Stream,
    telemetry::tracing::{self, warn},
};
use rama_http::{
    headers::authorization::UserCredInfo,
    layer::firewall::{FirewallLayer, FirewallStoreBackend},
    matcher::WhiteListedDomainsMatcher,
};
use rama_net::{
    socket::Interface,
    stream::SocketInfo,
    user::{self, Basic, authority::Authorizer},
};
use rama_tcp::{client::service::TcpConnector, server::TcpListener};
use rama_utils::str::smol_str::ToSmolStr as _;
use std::{fmt, ops::Deref, sync::Arc};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerType {
    Primary,
    Fallback,
}

/// Socks5 server implementation of [RFC 1928]
///
/// [RFC 1928]: https://datatracker.ietf.org/doc/html/rfc1928
///
/// An instance constructed with [`Socks5Acceptor::new`]
/// is one that accepts none of the available [`Command`]s,
/// until you embed one or more of: connector, binder and udp associator.
///
/// # [`Default`]
///
/// The [`Default`] implementation of the [`Socks5Acceptor`] only
/// supports the [`Command::Connect`] method using the [`DefaultConnector`],
/// but custom connectors as well as binders and udp associators
/// are optionally possible.
#[derive(Debug, Clone)]
pub struct Socks5Acceptor<A = ()> {
    pub exec: Executor,
    pub auth: A,
    pub firewall: FirewallLayer,
    pub domain_matcher: WhiteListedDomainsMatcher,
    pub server_type: ServerType,
}

impl<A> Socks5Acceptor<A> {
    /// Create a new [`Socks5Acceptor`] which supports none of the valid [`Command`]s.
    ///
    /// Use [`Socks5Acceptor::default`] instead if you wish to create a default
    /// [`Socks5Acceptor`] which can be used as a simple and honest byte-byte proxy.
    #[must_use]
    pub fn new(
        exec: Executor,
        auth: A,
        firewall: FirewallLayer,
        domain_matcher: WhiteListedDomainsMatcher,
        server_type: ServerType,
    ) -> Self {
        Self {
            exec,
            auth,
            firewall,
            domain_matcher,
            server_type,
        }
    }

    #[must_use]
    pub fn with_executor(self, executor: Executor) -> Self {
        Self {
            exec: executor,
            auth: self.auth,
            firewall: self.firewall,
            domain_matcher: self.domain_matcher,
            server_type: self.server_type,
        }
    }

    #[inline]
    #[must_use]
    pub fn with_default_executor(self) -> Self {
        Self {
            exec: Executor::default(),
            auth: self.auth,
            firewall: self.firewall,
            domain_matcher: self.domain_matcher,
            server_type: self.server_type,
        }
    }
}

thread_local! {
    static API_KEY_BUFFER: std::cell::RefCell<String> = std::cell::RefCell::new(String::with_capacity(32));
    static HOSTNAME_BUFFER: std::cell::RefCell<String> = std::cell::RefCell::new(String::with_capacity(64));
    static IP_ADDRESS_BUFFER: std::cell::RefCell<String> = std::cell::RefCell::new(String::with_capacity(64));
    static IP_WISE_VIOLATION_BUFFER: std::cell::RefCell<String> = std::cell::RefCell::new(String::with_capacity(64));
}

impl<A> Socks5Acceptor<A>
where
    A: Authorizer<user::Basic, Error: fmt::Debug>,
{
    pub async fn accept<S>(&self, mut stream: S) -> Result<(), Error>
    where
        S: Stream + Unpin + ExtensionsMut,
    {
        let Some(ip_addr) = stream
            .extensions()
            .get::<SocketInfo>()
            .map(|info| info.peer_addr().ip_addr.to_smolstr())
        else {
            return Err(Error::aborted("no socket info found"));
        };

        let client_header = client::Header::read_from(&mut stream)
            .await
            .map_err(|err| Error::protocol(err).with_context("read client header"))?;

        let (negotiated_method, maybe_ext) = self
            .handle_method(&client_header.methods, &mut stream, ip_addr.as_str())
            .await?;

        let Some(ext) = maybe_ext else {
            return Err(Error::aborted(
                "user creds extension not found, maybe a failed authentication",
            )
            .with_context("failed authentication"));
        };

        let Some(user) = ext.get::<UserCredInfo<Basic>>() else {
            return Err(Error::aborted(
                "user creds info basic not found, maybe a failed authentication",
            )
            .with_context("failed authentication"));
        };

        tracing::trace!(
            "socks5 server: headers exchanged negotiated method = {negotiated_method:?} (for client methods: {:?}",
            client_header.methods,
        );

        let client_request = client::Request::read_from(&mut stream)
            .await
            .map_err(|err| Error::protocol(err).with_context("read client request"))?;
        tracing::trace!(
            "socks5 server w/ destination {} and negotiated method {:?} (for client methods: {:?}): client request received cmd {:?}",
            client_request.destination,
            negotiated_method,
            client_header.methods,
            client_request.command,
        );

        let is_allowed_domain = self
            .domain_matcher
            .matches_host_user(&client_request.destination.host, user);

        let connector = match self.server_type {
            ServerType::Primary => DefaultConnector::default()
                .with_connector(TcpConnector::default().with_connector(user.primary_connector())),
            ServerType::Fallback => DefaultConnector::default()
                .with_connector(TcpConnector::default().with_connector(user.secondary_connector())),
        };

        stream.extensions_mut().extend(ext);

        let host = client_request.destination.host.to_str();

        let is_allowed_by_firewall = self
            .ip_host_firewall(host.deref(), ip_addr.as_str())
            .await
            .is_ok();

        if !is_allowed_by_firewall
            || !is_allowed_domain
            || !matches!(client_request.command, Command::Connect)
        {
            tracing::debug!(
                "socks5 server w/ destination {} for negotiated method: {:?} (for client methods: {:?}): abort: bind, udpassociate and unknown command {:?} not supported",
                client_request.destination,
                negotiated_method,
                client_header.methods,
                client_request.command,
            );

            Reply::error_reply(ReplyKind::CommandNotSupported)
                .write_to(&mut stream)
                .await
                .map_err(|err| {
                    Error::io(err).with_context(
                        "write server reply: bind, udpassociate and unknown command not supported",
                    )
                })?;
            return Err(
                Error::aborted("bind, udpassociate and unknown command not supported")
                    .with_context(ReplyKind::CommandNotSupported),
            );
        }
        connector
            .accept_connect(stream, client_request.destination)
            .await
    }

    pub async fn ip_host_firewall(&self, host: &str, ip_addr: &str) -> Result<(), BoxError> {
        let is_in_allowed_list = match &self.firewall.allowed_list.backend {
            FirewallStoreBackend::RwLock(store) => {
                let data_guard = store.read().await;
                data_guard.contains(ip_addr)
            }
            FirewallStoreBackend::ArcSwap(store) => {
                let data_guard = store.load();
                data_guard.contains(ip_addr)
            }
            FirewallStoreBackend::ArcShift(store) => {
                let data_guard = store.shared_get();
                data_guard.contains(ip_addr)
            }
        };

        if is_in_allowed_list {
            return Ok(());
        }

        let is_in_blocked_list = match &self.firewall.blocked_list.backend {
            FirewallStoreBackend::RwLock(store) => {
                let data_guard = store.read().await;
                data_guard.contains(ip_addr) || data_guard.contains(host)
            }
            FirewallStoreBackend::ArcSwap(store) => {
                let data_guard = store.load();
                data_guard.contains(ip_addr) || data_guard.contains(host)
            }
            FirewallStoreBackend::ArcShift(store) => {
                let data_guard = store.shared_get();
                data_guard.contains(ip_addr) || data_guard.contains(host)
            }
        };

        if is_in_blocked_list {
            warn!(ip_addr = %ip_addr, host= %host, "Dropping Connection For Blacklisted Hostname or Malicious Peer IP Address");
            let ip_addr = IP_ADDRESS_BUFFER.with(|buffer| {
                let mut buffer = buffer.borrow_mut();
                buffer.clear();
                buffer.push_str(ip_addr);
                buffer.to_owned()
            });
            let hostname = HOSTNAME_BUFFER.with(|buffer| {
                let mut buffer = buffer.borrow_mut();
                buffer.clear();
                buffer.push_str(host);
                buffer.to_owned()
            });
            Err(BoxError::from(
                "drop connection for blacklisted hostname or malicious peer ip address",
            )
            .context_field("hostname", hostname)
            .context_field("ip_addr", ip_addr))
        } else if let Some(_is_ip_banned) = self.firewall.firewall.is_banned(ip_addr).await {
            let ban_info = self
                .firewall
                .firewall
                .record_violation(ip_addr)
                .await
                .context("ip address record violation entry ban_info not found")?;

            let ban_time = ban_info.calculate_ttl();

            warn!(ip_addr = %ip_addr, host= %host, ban_info = ?ban_info, ban_time = ?ban_time, "Dropping Connection For Malicious Blocked Peer IP Address, ReBanned Peer IP Address With Updated Ban Info");
            let ip_addr = IP_ADDRESS_BUFFER.with(|buffer| {
                let mut buffer = buffer.borrow_mut();
                buffer.clear();
                buffer.push_str(ip_addr);
                buffer.to_owned()
            });
            Err(
                BoxError::from("drop connection for blocked peer ip address")
                    .context_field("ip_addr", ip_addr),
            )
        } else if let Some(_is_host_banned) = self.firewall.firewall.is_banned(host).await {
            let ban_info = self
                .firewall
                .firewall
                .record_violation(host)
                .await
                .context("hostname record violation entry ban_info not found")?;

            let ban_time = ban_info.calculate_ttl();

            warn!(ip_addr = %ip_addr, host= %host, ban_info = ?ban_info, ban_time = ?ban_time, "Dropping Connection For Malicious Blocked Hostname, ReBanned Hostname With Updated Ban Info");
            let hostname = HOSTNAME_BUFFER.with(|buffer| {
                let mut buffer = buffer.borrow_mut();
                buffer.clear();
                buffer.push_str(host);
                buffer.to_owned()
            });
            Err(BoxError::from("drop connection for blocked hostname")
                .context_field("hostname", hostname))
        } else {
            Ok(())
        }
    }
}

impl<A: Authorizer<user::Basic, Error: fmt::Debug>> Socks5Acceptor<A> {
    async fn handle_method<S: Stream + Unpin>(
        &self,
        methods: &[SocksMethod],
        stream: &mut S,
        ip_addr: &str,
    ) -> Result<(SocksMethod, Option<Extensions>), Error> {
        let ip_wise_violation = IP_WISE_VIOLATION_BUFFER.with(|buf| {
            let mut buffer = buf.borrow_mut();
            buffer.clear();
            buffer.push_str("::");
            buffer.push_str(ip_addr);
            buffer.push_str("::");
            buffer.to_owned()
        });

        if methods.contains(&SocksMethod::UsernamePassword) {
            Header::new(SocksMethod::UsernamePassword)
                .write_to(stream)
                .await
                .map_err(|err| {
                    Error::io(err).with_context("write server reply: auth (username-password)")
                })?;

            let client_auth_req = client::UsernamePasswordRequest::read_from(stream)
                .await
                .map_err(|err| {
                    Error::protocol(err)
                        .with_context("read client auth sub-negotiation request: username-password")
                })?;

            tracing::trace!("Proxy credentials found");
            let api_key = client_auth_req.basic.username();
            let api_key = API_KEY_BUFFER.with(|buf| {
                let mut buffer = buf.borrow_mut();
                buffer.clear();
                buffer.push_str(api_key);
                buffer.to_owned()
            });
            let is_in_allowed_list = match &self.firewall.allowed_list.backend {
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

            let is_in_blocked_list = match &self.firewall.blocked_list.backend {
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
                warn!(api_key = %api_key, "Found Blacklisted API_KEY, socks5 acceptor's authorizer stopped inc request");
                UsernamePasswordResponse::new_invalid_credentails()
                    .write_to(stream)
                    .await
                    .map_err(|err| {
                        Error::io(err).with_context(
                            "write server auth sub-negotiation error response: unauthorized",
                        )
                    })?;
                return Err(Error::aborted(
                    "Found Blacklisted API_KEY, username-password: client unauthorized",
                ));
            }
            let is_un_banned = self.firewall.firewall.is_banned(&api_key).await;
            let is_ip_banned = self.firewall.firewall.is_banned(&ip_wise_violation).await;
            if !is_in_allowed_list && let Some(_un_ban_info) = is_un_banned {
                let ban_info = self
                    .firewall
                    .firewall
                    .record_violation(&api_key)
                    .await
                    .ok_or_else(|| Error::service("Failed to record violation for API_KEY"))?;
                let ban_time = ban_info.calculate_ttl();
                warn!(api_key = %api_key, ip_addr = %ip_addr, ban_info = ?ban_info, ban_time = ?ban_time, "Dropping Connection For Blocked API_KEY, ReBanned API_KEY With Updated Ban Info");

                if let Some(ip_ban_info) = is_ip_banned
                    && ip_ban_info.violation_count >= 3
                {
                    for _ in 0..ip_ban_info.violation_count {
                        self.firewall
                            .firewall
                            .record_violation(ip_addr)
                            .await
                            .ok_or_else(|| {
                                Error::service("Failed to record violation for IP address")
                            })?;
                    }
                    let ban_time = {
                        let seconds = 1u64 << ip_ban_info.violation_count.min(12);
                        std::time::Duration::from_secs(seconds * 60)
                    };
                    warn!(ip_addr = %ip_addr, ban_time = ?ban_time, "Multiple Failed Attempts, Possible BruteForce Attack with Worng Credentials, Banned IP Address with Ban Info");
                }

                UsernamePasswordResponse::new_invalid_credentails()
                    .write_to(stream)
                    .await
                    .map_err(|err| {
                        Error::io(err).with_context(
                            "write server auth sub-negotiation error response: unauthorized",
                        )
                    })?;
                return Err(Error::aborted(
                    "Found Blocked API_KEY or Possible BruteForce Attack with Worng Credentials, username-password: client unauthorized",
                ));
            }

            let user::authority::AuthorizeResult { result, .. } =
                self.auth.authorize(client_auth_req.basic).await;
            match result {
                Ok(maybe_ext) => {
                    tracing::trace!(
                        maybe_ext = ?maybe_ext,
                        "Proxy credentials successfully checked"
                    );
                    UsernamePasswordResponse::new_success()
                        .write_to(stream)
                        .await
                        .map_err(|err| {
                            Error::io(err)
                                .with_context("write server auth sub-negotiation success response")
                        })?;
                    Ok((SocksMethod::UsernamePassword, maybe_ext))
                }
                Err(err) => {
                    let ban_info = self
                        .firewall
                        .firewall
                        .record_violation(&api_key)
                        .await
                        .ok_or_else(|| Error::service("Failed to record violation for API_KEY"))?;
                    let ban_time = ban_info.calculate_ttl();
                    warn!(ip_addr = %ip_addr, api_key = %api_key, ban_info = ?ban_info, ban_time = ?ban_time, "Possible BruteForce Attack with Worng Credentials, Banned API_KEY with Ban Info");
                    let _ban_info = self
                        .firewall
                        .firewall
                        .record_violation(&ip_wise_violation)
                        .await
                        .ok_or_else(|| {
                            Error::service("Failed to record violation for IP address")
                        })?;
                    tracing::trace!("socks5 acceptor's authorizer stopped inc request: {err:?}");
                    UsernamePasswordResponse::new_invalid_credentails()
                        .write_to(stream)
                        .await
                        .map_err(|err| {
                            Error::io(err).with_context(
                                "write server auth sub-negotiation error response: unauthorized",
                            )
                        })?;
                    Err(Error::aborted("username-password: client unauthorized"))
                }
            }
        } else {
            let ban_info = self
                .firewall
                .firewall
                .record_violation(ip_addr)
                .await
                .ok_or_else(|| Error::service("Failed to record violation for IP address"))?;
            let ban_time = ban_info.calculate_ttl();
            warn!(ip_addr = %ip_addr, ban_info = ?ban_info, ban_time = ?ban_time, "Credentials is a must and required, Banned IP Address with Ban Info");
            Header::new(SocksMethod::NoAcceptableMethods)
                .write_to(stream)
                .await
                .map_err(|err| {
                    Error::io(err).with_context(
                        "write server auth sub-negotiation error response: no acceptable methods",
                    )
                })?;
            Err(Error::aborted(
                "username-password required but client doesn't support the method (auth == required)",
            ))
        }
    }
}

impl<A, S> Service<S> for Socks5Acceptor<A>
where
    A: Authorizer<user::Basic, Error: fmt::Debug>,
    S: Stream + Unpin + ExtensionsMut,
{
    type Output = ();
    type Error = Error;

    #[inline]
    fn serve(
        &self,
        stream: S,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + '_ {
        self.accept(stream)
    }
}

impl<A> Socks5Acceptor<A>
where
    A: Authorizer<user::Basic, Error: fmt::Debug>,
{
    /// Listen for connections on the given [`Interface`], serving Socks5(h) connections.
    ///
    /// It's a shortcut in case you don't need to operate on the transport layer directly.
    pub async fn listen<I>(self, interface: I) -> Result<(), BoxError>
    where
        I: TryInto<Interface, Error: Into<BoxError>>,
    {
        let tcp = TcpListener::bind(interface, self.exec.clone()).await?;
        tcp.serve(Arc::new(self)).await;
        Ok(())
    }
}
