use {
    crate::{TcpStream, client::TcpStreamConnector},
    rama_core::error::OpaqueError,
    rand::{
        rng,
        seq::{IndexedRandom as _, SliceRandom as _},
    },
    std::{
        fmt::Debug,
        net::SocketAddr,
        slice::{Iter, IterMut},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        vec::IntoIter,
    },
};

#[derive(Clone)]
pub enum PoolMode {
    Random,
    RoundRobin(Arc<AtomicUsize>),
}

impl Default for PoolMode {
    fn default() -> Self {
        Self::Random
    }
}

impl Debug for PoolMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Random => write!(f, "Random"),
            Self::RoundRobin(index) => write!(
                f,
                "RoundRobin(current_index: {})",
                index.load(Ordering::Relaxed)
            ),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TcpStreamConnectorPool<C> {
    mode: PoolMode,
    connectors: Vec<C>,
    fallback: Option<Vec<C>>,
}

impl<C> Default for TcpStreamConnectorPool<C> {
    fn default() -> Self {
        Self {
            mode: PoolMode::default(),
            connectors: Vec::new(),
            fallback: None,
        }
    }
}

impl<C> IntoIterator for TcpStreamConnectorPool<C> {
    type Item = C;
    type IntoIter = IntoIter<C>;

    fn into_iter(self) -> Self::IntoIter {
        self.connectors.into_iter()
    }
}

impl<'a, C> IntoIterator for &'a TcpStreamConnectorPool<C> {
    type Item = &'a C;
    type IntoIter = Iter<'a, C>;

    fn into_iter(self) -> Self::IntoIter {
        self.connectors.iter()
    }
}

impl<'a, C> IntoIterator for &'a mut TcpStreamConnectorPool<C> {
    type Item = &'a mut C;
    type IntoIter = IterMut<'a, C>;

    fn into_iter(self) -> Self::IntoIter {
        self.connectors.iter_mut()
    }
}

impl<C: TcpStreamConnector + Clone> TcpStreamConnectorPool<C> {
    pub fn new_random(connectors: Vec<C>) -> Self {
        Self::default().with_connectors(connectors)
    }

    pub fn new_round_robin(mut connectors: Vec<C>) -> Self {
        let index = Arc::new(AtomicUsize::new(0));
        connectors.shuffle(&mut rng());
        Self::default()
            .with_mode(PoolMode::RoundRobin(index))
            .with_connectors(connectors)
    }

    pub fn with_mode(mut self, mode: PoolMode) -> Self {
        self.mode = mode;
        self
    }

    pub fn with_connectors(mut self, connectors: Vec<C>) -> Self {
        self.connectors = connectors;
        self
    }

    pub fn with_fallback(mut self, fallback: Vec<C>) -> Self {
        self.fallback = Some(fallback);
        self
    }

    #[inline]
    pub fn get_connector(&self) -> Option<C> {
        if self.is_empty() {
            return None;
        }
        let connector = match &self.mode {
            PoolMode::Random => self.connectors.choose(&mut rng()),
            PoolMode::RoundRobin(counter) => {
                let current_index = counter.fetch_add(1, Ordering::Relaxed);
                let index = current_index % self.len();
                self.connectors.get(index)
            }
        };
        connector.cloned()
    }

    #[inline]
    pub fn get_fallback_connector(&self) -> Option<C> {
        match self.fallback {
            Some(ref fallback) if !fallback.is_empty() => fallback.choose(&mut rng()).cloned(),
            _ => None,
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.connectors.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.connectors.is_empty()
    }

    #[inline]
    pub fn iter(&self) -> Iter<'_, C> {
        self.connectors.iter()
    }

    #[inline]
    pub fn iter_mut(&mut self) -> IterMut<'_, C> {
        self.connectors.iter_mut()
    }
}

impl<C: TcpStreamConnector + Clone + Debug> TcpStreamConnector for TcpStreamConnectorPool<C>
where
    <C as TcpStreamConnector>::Error:
        From<OpaqueError> + std::fmt::Debug + std::fmt::Display + Send,
{
    type Error = <C as TcpStreamConnector>::Error;

    async fn connect(&self, addr: SocketAddr) -> Result<TcpStream, Self::Error> {
        let Some(connector) = self.get_connector() else {
            return Err(OpaqueError::from_display(
                "TcpStreamConnectorPool is empty - no connectors available for connection",
            )
            .into());
        };
        tracing::debug!(
            target: "tcp_connector_pool",
            connector = ?connector,
            destination = %addr,
            pool_mode = ?self.mode,
            "Selected connector for TCP connection"
        );
        match connector.connect(addr).await {
            Ok(stream) => {
                tracing::debug!(
                    target: "tcp_connector_pool",
                    destination = %addr,
                    connector = ?connector,
                    "primary connection successful"
                );
                Ok(stream)
            }
            Err(primary_err) => {
                tracing::warn!(
                    target: "tcp_connector_pool",
                    error = %primary_err,
                    connector = ?connector,
                    destination = %addr,
                    "primary connection failed"
                );
                if let Some(fallback_connector) = self.get_fallback_connector() {
                    tracing::info!(
                        target: "tcp_connector_pool",
                        fallback_connector = ?fallback_connector,
                        destination = %addr,
                        "attempting fallback connection"
                    );
                    match fallback_connector.connect(addr).await {
                        Ok(stream) => {
                            tracing::info!(
                                target: "tcp_connector_pool",
                                fallback_connector = ?fallback_connector,
                                destination = %addr,
                                "fallback connection successful"
                            );
                            Ok(stream)
                        }
                        Err(fallback_err) => {
                            tracing::error!(
                                target: "tcp_connector_pool",
                                primary_error = %primary_err,
                                fallback_error = ?fallback_err,
                                destination = %addr,
                                "all connection attempts failed"
                            );
                            Err(fallback_err)
                        }
                    }
                } else {
                    tracing::error!(
                        target: "tcp_connector_pool",
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

#[derive(Debug, Clone)]
pub struct TcpStreamConnectorWithFallback<C> {
    connector: C,
    fallback: C,
}

impl<C: TcpStreamConnector + Clone + Debug> TcpStreamConnector for TcpStreamConnectorWithFallback<C>
where
    <C as TcpStreamConnector>::Error:
        From<OpaqueError> + std::fmt::Debug + std::fmt::Display + Send,
{
    type Error = <C as TcpStreamConnector>::Error;

    async fn connect(&self, addr: SocketAddr) -> Result<TcpStream, Self::Error> {
        tracing::debug!(
            target: "tcp_connector_with_fallback",
            connector = ?self.connector,
            destination = %addr,
            "Selected connector for TCP connection"
        );
        match self.connector.connect(addr).await {
            Ok(stream) => {
                tracing::debug!(
                    target: "tcp_connector_with_fallback",
                    destination = %addr,
                    connector = ?self.connector,
                    "primary connection successful"
                );
                Ok(stream)
            }
            Err(primary_err) => {
                tracing::warn!(
                    target: "tcp_connector_with_fallback",
                    error = %primary_err,
                    connector = ?self.connector,
                    destination = %addr,
                    "primary connection failed"
                );
                tracing::info!(
                    target: "tcp_connector_with_fallback",
                    fallback_connector = ?self.fallback,
                    destination = %addr,
                    "attempting fallback connection"
                );
                match self.fallback.connect(addr).await {
                    Ok(stream) => {
                        tracing::info!(
                            target: "tcp_connector_with_fallback",
                            fallback_connector = ?self.fallback,
                            destination = %addr,
                            "fallback connection successful"
                        );
                        Ok(stream)
                    }
                    Err(fallback_err) => {
                        tracing::error!(
                            target: "tcp_connector_with_fallback",
                            primary_error = %primary_err,
                            fallback_error = ?fallback_err,
                            destination = %addr,
                            "all connection attempts failed"
                        );
                        Err(fallback_err)
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{IpCidrConExt, IpCidrConnector, ipv4_from_extension};
    use rama_net::{
        address::SocketAddress,
        stream::dep::ipnet::{Ipv4Net, Ipv6Net},
    };
    use std::str::FromStr as _;

    fn init_tracing() {
        let subscriber = tracing_subscriber::fmt::Subscriber::builder()
            .with_max_level(tracing::Level::TRACE)
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
    }

    #[test]
    fn test_connectors_pool() {
        init_tracing();
        let connectors = vec![
            SocketAddress::from_str("127.0.0.1:8080").unwrap(),
            SocketAddress::from_str("127.0.0.1:8081").unwrap(),
            SocketAddress::from_str("127.0.0.1:8082").unwrap(),
            SocketAddress::from_str("127.0.0.1:8083").unwrap(),
            SocketAddress::from_str("127.0.0.1:8084").unwrap(),
            SocketAddress::from_str("127.0.0.1:8085").unwrap(),
        ];
        let mut pool = TcpStreamConnectorPool::new_random(connectors.clone());
        assert_eq!(
            pool.len(),
            6,
            "Pool should contain exactly 6 connectors after initialization"
        );
        assert!(
            !pool.is_empty(),
            "Pool should not be empty after adding connectors"
        );

        for i in 0..10 {
            let random_connector = pool.get_connector();
            tracing::info!("Random connector iteration {}: {:?}", i, random_connector);
            assert!(
                random_connector.is_some(),
                "Random connector should always be available from non-empty pool (iteration {})",
                i
            );
        }
        pool = TcpStreamConnectorPool::new_round_robin(connectors);
        assert_eq!(
            pool.len(),
            6,
            "RoundRobin pool should maintain same size as Random pool"
        );
        for i in 0..10 {
            let round_robin_connector = pool.get_connector();
            tracing::info!(
                "RoundRobin connector iteration {}: {:?}",
                i,
                round_robin_connector
            );
            assert!(
                round_robin_connector.is_some(),
                "RoundRobin connector should always be available from non-empty pool (iteration {})",
                i
            );
        }
    }

    #[test]
    fn test_ip_cidr_connectors_pool() {
        init_tracing();
        let connectors = vec![
            IpCidrConnector::new_ipv4(
                "192.168.1.0/24"
                    .parse::<Ipv4Net>()
                    .expect("Failed to parse IPv4 CIDR - invalid test configuration"),
            ),
            IpCidrConnector::new_ipv6(
                "2001:470:e953::/48"
                    .parse::<Ipv6Net>()
                    .expect("Failed to parse IPv6 CIDR - invalid test configuration"),
            ),
        ];
        let mut pool = TcpStreamConnectorPool::new_random(connectors.clone());
        assert_eq!(
            pool.len(),
            2,
            "CIDR pool should contain exactly 2 connectors (IPv4 + IPv6)"
        );
        for i in 0..10 {
            let random_connector = pool.get_connector().map(|c| c.get_connector());
            tracing::info!(
                "Random CIDR connector iteration {}: {:?}",
                i,
                random_connector
            );
            assert!(
                random_connector.is_some(),
                "Random CIDR connector resolution should succeed (iteration {})",
                i
            );
        }
        pool = TcpStreamConnectorPool::new_round_robin(connectors);
        for i in 0..10 {
            let round_robin_connector = pool.get_connector().map(|c| c.get_connector());
            tracing::info!(
                "RoundRobin CIDR connector iteration {}: {:?}",
                i,
                round_robin_connector
            );
            assert!(
                round_robin_connector.is_some(),
                "RoundRobin CIDR connector resolution should succeed (iteration {})",
                i
            );
        }
    }

    #[test]
    fn test_cidr_cycle() {
        init_tracing();

        let cidr = "101.30.16.0/20"
            .parse::<Ipv4Net>()
            .expect("Failed to parse test CIDR - invalid network specification");
        let capacity = (1u32 << (32 - cidr.prefix_len())) - 1;
        tracing::info!(
            "Testing CIDR {} with capacity {} addresses (network length: {} bits, host bits: {} bits)",
            cidr,
            capacity,
            cidr.prefix_len(),
            32 - cidr.prefix_len()
        );
        for i in 0..5000 {
            let addr = ipv4_from_extension(
                &cidr,
                None,
                Some(IpCidrConExt::Session((i % capacity) as u64)),
            );
            if i % 1000 == 0 {
                tracing::info!(
                    "CIDR cycle iteration {}: IP address {:?} (session_id: {}, capacity: {})",
                    i,
                    addr,
                    i % capacity,
                    capacity
                );
            }
        }
        tracing::info!(
            "Completed CIDR cycling test: 5000 iterations across {} address capacity ({:.1}x capacity coverage)",
            capacity,
            5000.0 / capacity as f64
        );
    }

    #[test]
    fn test_pool_edge_cases() {
        init_tracing();

        tracing::info!("Testing empty pool edge case - validating graceful degradation");
        let empty_pool = TcpStreamConnectorPool::<SocketAddress>::default();
        assert!(
            empty_pool.is_empty(),
            "Empty pool should report itself as empty"
        );
        assert_eq!(empty_pool.len(), 0, "Empty pool should report zero length");
        let empty_result = empty_pool.get_connector();
        assert!(
            empty_result.is_none(),
            "Empty pool should return None rather than panicking or providing invalid connector"
        );

        tracing::info!("Empty pool validation completed successfully");
        tracing::info!(
            "Testing single connector edge case - validating minimal configuration behavior"
        );

        let single_connector = vec![SocketAddress::from_str("127.0.0.1:8080").unwrap()];
        let single_pool = TcpStreamConnectorPool::new_random(single_connector);
        assert!(
            !single_pool.is_empty(),
            "Single connector pool should not report as empty"
        );
        assert_eq!(
            single_pool.len(),
            1,
            "Single connector pool should report length of 1"
        );
        for iteration in 0..5 {
            let connector = single_pool.get_connector();
            tracing::info!(
                "Single pool connector iteration {}: {:?}",
                iteration,
                connector
            );
            assert!(
                connector.is_some(),
                "Single connector pool should always provide the same connector (iteration {})",
                iteration
            );
            if let Some(conn) = connector {
                assert_eq!(
                    conn.to_string(),
                    "127.0.0.1:8080",
                    "Single connector pool should always return the same connector address"
                );
            }
        }

        tracing::info!("Single connector pool validation completed successfully");
    }

    #[test]
    fn test_round_robin_distribution() {
        init_tracing();
        let mut connectors = vec![
            SocketAddress::from_str("127.0.0.1:8001").unwrap(),
            SocketAddress::from_str("127.0.0.1:8002").unwrap(),
            SocketAddress::from_str("127.0.0.1:8003").unwrap(),
        ];

        let pool = TcpStreamConnectorPool::new_round_robin(connectors.clone());
        connectors = pool.connectors.clone();

        tracing::info!(
            "Starting RoundRobin distribution test with {} connectors across {} cycles",
            connectors.len(),
            3
        );

        for cycle in 0..3 {
            tracing::info!("Beginning cycle {} of RoundRobin distribution test", cycle);
            for (expected_idx, expected_connector) in connectors.iter().enumerate() {
                let actual_connector = pool.get_connector().unwrap();

                tracing::info!(
                    "Cycle {}, Position {}: Expected {:?}, Got {:?}, Match: {}",
                    cycle,
                    expected_idx,
                    expected_connector,
                    actual_connector,
                    &actual_connector == expected_connector
                );
                assert_eq!(
                    &actual_connector, expected_connector,
                    "RoundRobin distribution failure: cycle {}, position {} - expected {:?}, got {:?}",
                    cycle, expected_idx, expected_connector, actual_connector
                );
            }

            tracing::info!(
                "Cycle {} completed successfully - all connectors matched expectations",
                cycle
            );
        }
        tracing::info!(
            "RoundRobin distribution test completed successfully: {} cycles, {} total selections, perfect distribution achieved",
            3,
            3 * connectors.len()
        );
    }
}
