use {
    super::{
        PoolMode,
        utils::{IpCidrConExt, ipv4_from_extension, ipv6_from_extension},
    },
    crate::{TcpStream, client::TcpStreamConnector},
    rama_core::{error::OpaqueError, telemetry::tracing},
    rama_net::{
        address::SocketAddress,
        stream::dep::ipnet::{IpNet, Ipv4Net, Ipv6Net},
    },
    std::{
        collections::HashSet,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::atomic::Ordering,
    },
};

#[derive(Debug, Clone)]
pub struct IpCidrConnector {
    mode: PoolMode,
    ip_cidr: IpNet,
    cidr_range: Option<u8>,
    fallback: Option<IpNet>,
    excluded: Option<HashSet<IpAddr>>,
    extension: Option<IpCidrConExt>,
    capacity: u128,
}

impl Default for IpCidrConnector {
    fn default() -> Self {
        Self {
            mode: PoolMode::Random,
            ip_cidr: IpNet::V4(
                Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0)
                    .expect("Failed to parse unspecified IPv4 address"),
            ),
            cidr_range: None,
            fallback: None,
            excluded: None,
            extension: None,
            capacity: u128::from(u32::MAX),
        }
    }
}

impl IpCidrConnector {
    pub fn new(ip_cidr: IpNet) -> Self {
        let capacity = Self::calculate_capacity(&ip_cidr);
        Self {
            ip_cidr,
            capacity,
            ..Default::default()
        }
    }

    pub fn new_ipv4(ip_cidr: Ipv4Net) -> Self {
        let capacity = Self::calculate_capacity(&IpNet::V4(ip_cidr));
        Self {
            ip_cidr: IpNet::V4(ip_cidr),
            capacity,
            ..Default::default()
        }
    }

    pub fn new_ipv6(ip_cidr: Ipv6Net) -> Self {
        let capacity = Self::calculate_capacity(&IpNet::V6(ip_cidr));
        Self {
            ip_cidr: IpNet::V6(ip_cidr),
            capacity,
            ..Default::default()
        }
    }

    pub fn with_mode(mut self, mode: PoolMode) -> Self {
        self.mode = mode;
        self
    }

    pub fn with_cidr_range(mut self, cidr_range: Option<u8>) -> Self {
        if let Some(range) = cidr_range {
            match self.ip_cidr {
                IpNet::V4(_) => {
                    assert!((range <= 32), "IPv4 CIDR range cannot exceed 32 bits");
                }
                IpNet::V6(_) => {
                    assert!((range <= 128), "IPv6 CIDR range cannot exceed 128 bits");
                }
            }
        }
        self.cidr_range = cidr_range;
        self
    }

    pub fn with_fallback(mut self, fallback: Option<IpNet>) -> Self {
        self.fallback = fallback;
        self
    }

    pub fn with_excluded(mut self, excluded: Option<Vec<IpAddr>>) -> Self {
        self.excluded = excluded.map(|vec| vec.into_iter().collect());
        self
    }

    pub fn with_extension(mut self, extension: Option<IpCidrConExt>) -> Self {
        self.extension = extension;
        self
    }

    pub fn get_connector(&self) -> (SocketAddress, Option<SocketAddress>) {
        const MAX_RETRIES: usize = 1000;

        for _ in 0..MAX_RETRIES {
            let ip_addr = self.generate_ip_address();
            if self.excluded.is_none() {
                return self.create_socket_addresses(ip_addr);
            }
            if let Some(ref excluded) = self.excluded {
                if !excluded.contains(&ip_addr) {
                    return self.create_socket_addresses(ip_addr);
                }
            }
        }
        let ip_addr = self.generate_ip_address();
        self.create_socket_addresses(ip_addr)
    }

    #[inline]
    fn calculate_capacity(ip_cidr: &IpNet) -> u128 {
        if ip_cidr.prefix_len() >= ip_cidr.max_prefix_len() {
            return 1;
        }
        match ip_cidr {
            IpNet::V4(_) => {
                if ip_cidr.prefix_len() == 0 {
                    u128::from(u32::MAX)
                } else {
                    u128::from((1u64 << (32 - ip_cidr.prefix_len())) - 1)
                }
            }
            IpNet::V6(_) => {
                if ip_cidr.prefix_len() == 0 {
                    u128::MAX
                } else {
                    (1u128 << (128 - ip_cidr.prefix_len())).saturating_sub(1)
                }
            }
        }
    }

    #[inline]
    fn generate_ip_address(&self) -> IpAddr {
        match (&self.mode, &self.ip_cidr) {
            (PoolMode::Random, IpNet::V4(cidr)) => {
                IpAddr::V4(ipv4_from_extension(cidr, self.cidr_range, self.extension))
            }
            (PoolMode::Random, IpNet::V6(cidr)) => {
                IpAddr::V6(ipv6_from_extension(cidr, self.cidr_range, self.extension))
            }
            (PoolMode::RoundRobin(index), IpNet::V4(cidr)) => {
                let current_idx = index.fetch_add(1, Ordering::Relaxed);
                tracing::debug!("Round-robin index: {}", current_idx);
                tracing::debug!("Round-robin capacity: {}", self.capacity);
                let session_id = (current_idx % self.capacity as usize) as u64;
                let ipv4_addr =
                    ipv4_from_extension(cidr, None, Some(IpCidrConExt::Session(session_id)));
                IpAddr::V4(ipv4_addr)
            }
            (PoolMode::RoundRobin(index), IpNet::V6(cidr)) => {
                let current_idx = index.fetch_add(1, Ordering::Relaxed);
                let session_id =
                    u64::try_from(current_idx as u128 % self.capacity).unwrap_or(u64::MAX);
                let ipv6_addr =
                    ipv6_from_extension(cidr, None, Some(IpCidrConExt::Session(session_id)));
                IpAddr::V6(ipv6_addr)
            }
        }
    }

    #[inline]
    fn generate_fallback_ip_address(&self) -> Option<IpAddr> {
        match &self.fallback {
            Some(IpNet::V4(cidr)) => Some(IpAddr::V4(ipv4_from_extension(
                cidr,
                self.cidr_range,
                self.extension,
            ))),
            Some(IpNet::V6(cidr)) => Some(IpAddr::V6(ipv6_from_extension(
                cidr,
                self.cidr_range,
                self.extension,
            ))),
            None => None,
        }
    }

    #[inline]
    fn create_socket_addresses(&self, ip_addr: IpAddr) -> (SocketAddress, Option<SocketAddress>) {
        let primary = SocketAddress::new(ip_addr, 0);
        let fallback = self
            .generate_fallback_ip_address()
            .map(|fb| SocketAddress::new(fb, 0));
        (primary, fallback)
    }
}

impl TcpStreamConnector for IpCidrConnector {
    type Error = OpaqueError;

    async fn connect(&self, addr: SocketAddr) -> Result<TcpStream, Self::Error> {
        let (bind_addr, fallback) = self.get_connector();

        tracing::debug!(
            target: "ip_cidr_connector",
            %addr,
            %bind_addr,
            "attempting primary connection"
        );

        match bind_addr.connect(addr).await {
            Ok(stream) => {
                tracing::debug!(
                    target: "ip_cidr_connector",
                    %addr,
                    %bind_addr,
                    "primary connection successful"
                );
                Ok(stream)
            }
            Err(primary_err) => {
                tracing::warn!(
                    target: "ip_cidr_connector",
                    error = %primary_err,
                    %addr,
                    %bind_addr,
                    "primary connection failed"
                );

                if let Some(fallback_addr) = fallback {
                    tracing::info!(
                        target: "ip_cidr_connector",
                        %addr,
                        %fallback_addr,
                        "attempting fallback connection"
                    );

                    match fallback_addr.connect(addr).await {
                        Ok(stream) => {
                            tracing::info!(
                                target: "ip_cidr_connector",
                                %addr,
                                %fallback_addr,
                                "fallback connection successful"
                            );
                            Ok(stream)
                        }
                        Err(fallback_err) => {
                            tracing::error!(
                                target: "ip_cidr_connector",
                                primary_error = %primary_err,
                                fallback_error = %fallback_err,
                                %addr,
                                "all connection attempts failed"
                            );
                            Err(fallback_err)
                        }
                    }
                } else {
                    tracing::error!(
                        target: "ip_cidr_connector",
                        error = %primary_err,
                        %addr,
                        "connection failed with no fallback configured"
                    );
                    Err(primary_err)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        str::FromStr,
        sync::{Arc, atomic::AtomicUsize},
    };

    fn init_tracing() {
        let subscriber = tracing_subscriber::fmt::Subscriber::builder()
            .with_max_level(tracing::Level::TRACE)
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
    }

    #[test]
    fn test_ipcidr_connectors_comprehensive() {
        init_tracing();
        let test_cases = vec![
            (
                "IPv4 /24 network",
                IpCidrConnector::new_ipv4(
                    "192.168.1.0/24"
                        .parse::<Ipv4Net>()
                        .expect("Failed to parse IPv4 CIDR"),
                ),
            ),
            (
                "IPv6 /48 network",
                IpCidrConnector::new_ipv6(
                    "2001:470:e953::/48"
                        .parse::<Ipv6Net>()
                        .expect("Failed to parse IPv6 CIDR"),
                ),
            ),
        ];

        for (test_name, mut connector) in test_cases {
            tracing::info!("Testing: {} - {:?}", test_name, connector);
            tracing::info!("Testing random mode for {}", test_name);
            for i in 0..10 {
                let (random_connector, fallback) = connector.get_connector();
                tracing::debug!("Random selection {}: {:?}", i + 1, random_connector);
                assert!(
                    fallback.is_none(),
                    "No fallback should be configured initially"
                );
            }
            tracing::info!("Testing round-robin mode for {}", test_name);
            connector.mode = PoolMode::RoundRobin(Arc::new(AtomicUsize::new(0)));
            connector.fallback = "2001:470:e953:f179::/64".parse::<IpNet>().ok();
            let excluded_addrs = vec![connector.ip_cidr.addr()];
            connector.excluded = Some(excluded_addrs.into_iter().collect());
            for i in 0..10 {
                let (round_robin_connector, fallback) = connector.get_connector();
                tracing::debug!(
                    "Round-robin selection {}: {:?}, Fallback: {:?}",
                    i + 1,
                    round_robin_connector,
                    fallback
                );
                assert!(fallback.is_some(), "Fallback should be configured");
                let selected_ip = round_robin_connector.ip_addr;
                assert_ne!(selected_ip, connector.ip_cidr.addr());
            }
        }
    }

    #[test]
    fn test_single_ip_ipcidr_connectors_with_fallback() {
        init_tracing();

        let test_cases = vec![(
            "IPv4 /32 single-host network",
            IpCidrConnector::new_ipv4("192.168.1.15/32".parse::<Ipv4Net>().expect(
                "Failed to parse IPv4 /32 CIDR - this indicates a fundamental parsing error",
            )),
        )];

        for (test_name, mut connector) in test_cases {
            tracing::info!(
                "Initiating single-IP CIDR validation: {} - Configuration: {:?}",
                test_name,
                connector
            );
            tracing::info!(
                "Phase 1: Baseline random mode validation for single-IP determinism - {}",
                test_name
            );

            for iteration in 0..10 {
                let (selected_address, fallback_address) = connector.get_connector();

                tracing::debug!(
                    "Random mode iteration {} of 10: Selected address={:?}, Expected IP=192.168.1.15",
                    iteration + 1,
                    selected_address
                );

                assert_eq!(
                    selected_address.ip_addr,
                    IpAddr::V4("192.168.1.15".parse().unwrap()),
                    "Single-IP CIDR must always return the exact configured address"
                );

                assert!(
                    fallback_address.is_none(),
                    "Initial configuration should have no fallback address configured"
                );
            }

            tracing::info!(
                "Phase 2: Cross-protocol fallback configuration and validation - {}",
                test_name
            );

            connector.mode = PoolMode::RoundRobin(Arc::new(AtomicUsize::new(0)));
            tracing::debug!("Configured round-robin mode with atomic counter initialized to 0");

            connector.fallback = IpAddr::from_str("2001:470:e953::ffff").ok().map(|addr| {
                let addr = IpNet::from(addr);
                tracing::info!(
                    "Cross-protocol fallback configured: IPv4 primary -> IPv6 fallback ({})",
                    addr
                );
                addr
            });

            for iteration in 0..10 {
                let (primary_address, fallback_address) = connector.get_connector();

                tracing::debug!(
                    "Round-robin iteration {} of 10: Primary={:?}, Fallback={:?}",
                    iteration + 1,
                    primary_address,
                    fallback_address
                );

                assert_eq!(
                    primary_address.ip_addr,
                    IpAddr::V4("192.168.1.15".parse().unwrap()),
                    "Round-robin mode with single IP must consistently return the configured address"
                );

                assert!(
                    fallback_address.is_some(),
                    "Cross-protocol fallback must be configured and available for high-availability scenarios"
                );

                if let Some(fallback) = fallback_address {
                    assert_eq!(
                        fallback.ip_addr,
                        IpAddr::V6("2001:470:e953::ffff".parse().unwrap()),
                        "IPv6 fallback address must match the configured Hurricane Electric tunnel endpoint"
                    );

                    tracing::debug!(
                        "Cross-protocol fallback validation successful: IPv6 address {} properly configured",
                        fallback.ip_addr
                    );
                }
            }

            tracing::info!(
                "Single-IP CIDR connector validation completed successfully for {}",
                test_name
            );
        }
    }

    #[test]
    fn test_capacity_calculations() {
        let ipv4_24 = IpCidrConnector::new_ipv4("192.168.1.0/24".parse().unwrap());
        assert_eq!(ipv4_24.capacity, 255);
        let ipv4_16 = IpCidrConnector::new_ipv4("10.0.0.0/16".parse().unwrap());
        assert_eq!(ipv4_16.capacity, 65535);
        let ipv6_64 = IpCidrConnector::new_ipv6("2001:db8::/64".parse().unwrap());
        assert_eq!(ipv6_64.capacity, (1u128 << 64) - 1);
    }

    #[test]
    #[should_panic(expected = "IPv4 CIDR range cannot exceed 32 bits")]
    fn test_invalid_ipv4_cidr_range() {
        let _unused =
            IpCidrConnector::new_ipv4("192.168.1.0/24".parse().unwrap()).with_cidr_range(Some(33));
    }

    #[test]
    #[should_panic(expected = "IPv6 CIDR range cannot exceed 128 bits")]
    fn test_invalid_ipv6_cidr_range() {
        let _unused =
            IpCidrConnector::new_ipv6("2001:db8::/64".parse().unwrap()).with_cidr_range(Some(129));
    }
}
