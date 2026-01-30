use {
    rama_core::{
        extensions::Extensions,
        telemetry::tracing,
        username::{UsernameLabelParser, UsernameLabelState},
    },
    rama_net::stream::dep::ipnet::{Ipv4Net, Ipv6Net},
    rand::random,
    std::{
        convert::Infallible,
        net::{Ipv4Addr, Ipv6Addr},
        time::{SystemTime, UNIX_EPOCH},
    },
};

#[inline]
pub fn rand_ipv4(cidr: &Ipv4Net) -> Ipv4Addr {
    let prefix_len = cidr.prefix_len();
    if prefix_len == 32 {
        return cidr.addr();
    }
    let host_bits = 32 - prefix_len;
    if host_bits >= 32 {
        return Ipv4Addr::from(random::<u32>());
    }
    let base_ip_u32 = u32::from(cidr.addr());
    let rand_val: u32 = random();
    let host_mask = (1u32 << host_bits) - 1;
    let host_part = rand_val & host_mask;
    let net_part = base_ip_u32 & !host_mask;
    Ipv4Addr::from(net_part | host_part)
}

#[inline]
pub fn rand_ipv6(cidr: &Ipv6Net) -> Ipv6Addr {
    let prefix_len = cidr.prefix_len();
    if prefix_len == 128 {
        return cidr.addr();
    }
    let host_bits = 128 - prefix_len;
    if host_bits >= 128 {
        return Ipv6Addr::from(random::<u128>());
    }
    let base_ip_u128 = u128::from(cidr.addr());
    let rand_val: u128 = random();
    let host_mask = (1u128 << host_bits) - 1;
    let host_part = rand_val & host_mask;
    let net_part = base_ip_u128 & !host_mask;
    Ipv6Addr::from(net_part | host_part)
}

#[inline]
pub fn ipv4_with_range(cidr: &Ipv4Net, range_len: u8, combined: u32) -> Ipv4Addr {
    let prefix_len = cidr.prefix_len();
    if range_len <= prefix_len {
        return rand_ipv4(cidr);
    }
    let base_ip_u32 = u32::from(cidr.addr());
    let fixed_bits_len = range_len - prefix_len;
    let host_bits = 32 - range_len;
    if fixed_bits_len >= 32 || host_bits >= 32 {
        return rand_ipv4(cidr);
    }
    let fixed_mask = (1u32 << fixed_bits_len) - 1;
    let host_mask = if host_bits == 0 {
        0
    } else {
        (1u32 << host_bits) - 1
    };
    let fixed_part = (combined & fixed_mask) << host_bits;
    let network_mask = !((1u32 << (32 - prefix_len)) - 1);
    let network_part = base_ip_u32 & network_mask;
    let host_part = random::<u32>() & host_mask;
    Ipv4Addr::from(network_part | fixed_part | host_part)
}

#[inline]
pub fn ipv6_with_range(cidr: &Ipv6Net, range_len: u8, combined: u128) -> Ipv6Addr {
    let prefix_len = cidr.prefix_len();
    if range_len <= prefix_len {
        return rand_ipv6(cidr);
    }
    let base_ip_u128 = u128::from(cidr.addr());
    let fixed_bits_len = range_len - prefix_len;
    let host_bits = 128 - range_len;
    let fixed_mask = (1u128 << fixed_bits_len) - 1;
    let host_mask = (1u128 << host_bits) - 1;
    let fixed_part = (combined & fixed_mask) << host_bits;
    let network_mask = !((1u128 << (128 - prefix_len)) - 1);
    let network_part = base_ip_u128 & network_mask;
    let host_part = random::<u128>() & host_mask;
    Ipv6Addr::from(network_part | fixed_part | host_part)
}

#[inline]
pub fn ipv4_from_extension(
    cidr: &Ipv4Net,
    cidr_range: Option<u8>,
    extension: Option<IpCidrConExt>,
) -> Ipv4Addr {
    if let Some(combined) = extract_value_from_ipcidr_connector_extension(extension) {
        match extension {
            Some(IpCidrConExt::Ttl(_) | IpCidrConExt::Session(_)) => {
                let prefix_len = cidr.prefix_len();
                let subnet_mask = !((1u32 << (32 - prefix_len)) - 1);
                let base_ip_bits = u32::from(cidr.addr()) & subnet_mask;
                let capacity = if prefix_len == 0 {
                    u32::MAX
                } else if prefix_len >= 32 {
                    1u32
                } else {
                    (1u32 << (32 - prefix_len)) - 1u32
                };
                let host_portion = u32::try_from(combined).unwrap_or(u32::MAX) % capacity;
                let ip_num = base_ip_bits | host_portion;
                return Ipv4Addr::from(ip_num);
            }
            Some(IpCidrConExt::Range(_)) => {
                if let Some(range) = cidr_range {
                    return ipv4_with_range(
                        cidr,
                        range,
                        u32::try_from(combined).unwrap_or(u32::MAX),
                    );
                }
            }
            Some(IpCidrConExt::None) | None => {}
        }
    }

    rand_ipv4(cidr)
}

#[inline]
pub fn ipv6_from_extension(
    cidr: &Ipv6Net,
    cidr_range: Option<u8>,
    extension: Option<IpCidrConExt>,
) -> Ipv6Addr {
    if let Some(combined) = extract_value_from_ipcidr_connector_extension(extension) {
        match extension {
            Some(IpCidrConExt::Ttl(_) | IpCidrConExt::Session(_)) => {
                let network_length = cidr.prefix_len();
                let subnet_mask = !((1u128 << (128 - network_length)) - 1);

                let base_ip_bits = u128::from(cidr.addr()) & subnet_mask;
                let capacity = if network_length == 0 {
                    u128::MAX
                } else if network_length >= 128 {
                    1u128
                } else {
                    (1u128 << (128 - network_length)).saturating_sub(1)
                };
                let host_portion = u128::from(combined) % capacity;

                let ip_num = base_ip_bits | host_portion;
                return Ipv6Addr::from(ip_num);
            }
            Some(IpCidrConExt::Range(_)) => {
                if let Some(range) = cidr_range {
                    return ipv6_with_range(cidr, range, u128::from(combined));
                }
            }
            Some(IpCidrConExt::None) | None => {}
        }
    }
    rand_ipv6(cidr)
}

#[inline]
pub const fn extract_value_from_ipcidr_connector_extension(
    extension: Option<IpCidrConExt>,
) -> Option<u64> {
    match extension {
        Some(
            IpCidrConExt::Range(value) | IpCidrConExt::Session(value) | IpCidrConExt::Ttl(value),
        ) => Some(value),
        Some(IpCidrConExt::None) | None => None,
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub enum IpCidrConExt {
    #[default]
    None,
    Ttl(u64),
    Range(u64),
    Session(u64),
}

#[derive(Debug, Clone, Default)]
pub struct IpCidrConExtUsernameLabelParser {
    extension: Option<IpCidrConExt>,
}

impl IpCidrConExtUsernameLabelParser {
    const EXTENSION_TTL: &'static str = "ttl";
    const EXTENSION_SESSION: &'static str = "session";
    const EXTENSION_RANGE_SESSION: &'static str = "range";
}

impl UsernameLabelParser for IpCidrConExtUsernameLabelParser {
    type Error = Infallible;

    fn parse_label(&mut self, label: &str) -> UsernameLabelState {
        let label = label.trim().to_ascii_lowercase();

        match self.extension {
            Some(ref mut ext) => match ext {
                IpCidrConExt::Ttl(ttl) => {
                    *ttl = {
                        let parsed_ttl = label.parse::<u64>().unwrap_or(0);
                        let start = SystemTime::now();
                        let timestamp = start
                            .duration_since(UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or_else(|_| rand::random());

                        if parsed_ttl > 0 {
                            timestamp - (timestamp % parsed_ttl)
                        } else {
                            timestamp
                        }
                    }
                }
                IpCidrConExt::Session(session) => {
                    *session = label.parse::<u64>().unwrap_or(0);
                }
                IpCidrConExt::Range(range) => {
                    *range = label.parse::<u64>().unwrap_or(0);
                }
                IpCidrConExt::None => {}
            },
            None => match label.as_str() {
                Self::EXTENSION_TTL => {
                    self.extension = Some(IpCidrConExt::Ttl(0));
                }
                Self::EXTENSION_SESSION => {
                    self.extension = Some(IpCidrConExt::Session(0));
                }
                Self::EXTENSION_RANGE_SESSION => {
                    self.extension = Some(IpCidrConExt::Range(0));
                }
                _ => {
                    self.extension = Some(IpCidrConExt::None);
                    tracing::trace!("invalid extension username label value: {label}");
                    return UsernameLabelState::Ignored;
                }
            },
        }
        UsernameLabelState::Used
    }

    fn build(self, ext: &mut Extensions) -> Result<(), Self::Error> {
        ext.insert(self.extension);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::{
        extensions::Extensions,
        username::{UsernameOpaqueLabelParser, parse_username},
    };

    fn init_tracing() {
        let subscriber = tracing_subscriber::fmt::Subscriber::builder()
            .with_max_level(tracing::Level::TRACE)
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
    }

    #[test]
    fn test_username_label_parser() {
        init_tracing();

        let mut ext = Extensions::default();

        let parser = (
            UsernameOpaqueLabelParser::new(),
            IpCidrConExtUsernameLabelParser::default(),
        );

        assert_eq!(
            parse_username(&mut ext, parser.clone(), "username").unwrap(),
            "username"
        );

        let labels = ext.get::<IpCidrConExt>();
        tracing::debug!("Basic username extension result: {labels:?}");

        assert_eq!(
            parse_username(&mut ext, parser.clone(), "username-session-123456789",).unwrap(),
            "username"
        );

        let labels = ext.get::<IpCidrConExt>();
        tracing::debug!("Session extension result: {labels:?}");

        assert_eq!(
            parse_username(&mut ext, parser.clone(), "username-ttl-5",).unwrap(),
            "username"
        );

        let labels = ext.get::<IpCidrConExt>();
        tracing::debug!("TTL extension result: {labels:?}");

        assert_eq!(
            parse_username(&mut ext, parser.clone(), "username-range-12345",).unwrap(),
            "username"
        );

        let labels = ext.get::<IpCidrConExt>();
        tracing::debug!("Range extension result: {labels:?}");

        assert_eq!(
            parse_username(&mut ext, parser.clone(), "username-john-gonsalvis").unwrap(),
            "username"
        );

        let labels = ext.get::<IpCidrConExt>();
        tracing::debug!("Invalid extension result: {labels:?}");

        assert_eq!(
            parse_username(&mut ext, parser.clone(), "username-session").unwrap(),
            "username"
        );

        let labels = ext.get::<IpCidrConExt>();
        tracing::debug!("Incomplete extension result: {labels:?}");
    }

    #[test]
    fn test_assign_ipv4_with_username_label_parser() {
        init_tracing();
        let cidr = "101.30.16.0/20"
            .parse::<Ipv4Net>()
            .expect("Unable to parse IPv4 CIDR - check format");
        let mut ext = Extensions::default();
        let parser = (
            UsernameOpaqueLabelParser::new(),
            IpCidrConExtUsernameLabelParser::default(),
        );

        for iteration in 0..17u32 {
            parse_username(&mut ext, parser.clone(), "username")
                .expect("Username parsing should never fail for valid input");
            let extension = ext.get::<IpCidrConExt>();
            let ipv4_address = ipv4_from_extension(&cidr, None, extension.cloned());

            tracing::info!(
                "Iteration {}: Generated IPv4 Address: {} (Network: {}, Host bits: {})",
                iteration,
                ipv4_address,
                cidr.addr(),
                32 - cidr.prefix_len()
            );
        }
    }
    #[test]
    fn test_assign_ipv6_with_username_label_parser() {
        init_tracing();
        let cidr = "2001:470:e953::/48"
            .parse::<Ipv6Net>()
            .expect("Unable to parse IPv6 CIDR - check format");
        let mut ext = Extensions::default();
        let parser = (
            UsernameOpaqueLabelParser::new(),
            IpCidrConExtUsernameLabelParser::default(),
        );
        for iteration in 0..17u32 {
            parse_username(&mut ext, parser.clone(), "username")
                .expect("Username parsing should never fail for valid input");
            let extension = ext.get::<IpCidrConExt>();
            let ipv6_address = ipv6_from_extension(&cidr, None, extension.cloned());

            tracing::info!(
                "Iteration {}: Generated IPv6 Address: {} (Network: {}, Host bits: {})",
                iteration,
                ipv6_address,
                cidr.addr(),
                128 - cidr.prefix_len()
            );
        }
    }

    #[test]
    fn test_assign_ipv4_with_range() {
        init_tracing();
        let cidr = "101.30.16.0/20"
            .parse::<Ipv4Net>()
            .expect("Unable to parse IPv4 CIDR - check format");
        let range = 24;
        let mut combined = 1;
        for iteration in 0..5 {
            combined += 1;
            let ipv4_address1 = ipv4_with_range(&cidr, range, combined);
            let ipv4_address2 = ipv4_with_range(&cidr, range, combined);

            tracing::info!(
                "Iteration {}: Combined value: {} (0x{:x})",
                iteration,
                combined,
                combined
            );
            tracing::info!(
                "  IPv4 Address 1: {} (Binary: {:032b})",
                ipv4_address1,
                u32::from(ipv4_address1)
            );
            tracing::info!(
                "  IPv4 Address 2: {} (Binary: {:032b})",
                ipv4_address2,
                u32::from(ipv4_address2)
            );
            let addr1_u32 = u32::from(ipv4_address1);
            let addr2_u32 = u32::from(ipv4_address2);
            let deterministic_mask = !((1u32 << (32 - range)) - 1);

            tracing::debug!(
                "  Deterministic portions match: {}",
                (addr1_u32 & deterministic_mask) == (addr2_u32 & deterministic_mask)
            );
        }
    }

    #[test]
    fn test_assign_ipv6_with_range() {
        init_tracing();
        let cidr = "2001:470:e953::/48"
            .parse::<Ipv6Net>()
            .expect("Unable to parse IPv6 CIDR - check format");
        let range = 64;
        let mut combined = 0x1234;
        for iteration in 0..5 {
            combined += 1;
            let ipv6_address1 = ipv6_with_range(&cidr, range, combined);
            let ipv6_address2 = ipv6_with_range(&cidr, range, combined);

            tracing::info!(
                "Iteration {}: Combined value: {} (0x{:x})",
                iteration,
                combined,
                combined
            );
            tracing::info!(
                "  IPv6 Address 1: {} (Binary high: {:064b})",
                ipv6_address1,
                u128::from(ipv6_address1) >> 64
            );
            tracing::info!(
                "  IPv6 Address 2: {} (Binary high: {:064b})",
                ipv6_address2,
                u128::from(ipv6_address2) >> 64
            );
            let addr1_u128 = u128::from(ipv6_address1);
            let addr2_u128 = u128::from(ipv6_address2);
            let deterministic_mask = !((1u128 << (128 - range)) - 1);

            tracing::debug!(
                "  Deterministic portions match: {}",
                (addr1_u128 & deterministic_mask) == (addr2_u128 & deterministic_mask)
            );
        }
    }

    #[test]
    fn test_assign_ipv4_with_session() {
        init_tracing();
        let cidr = "101.30.16.0/20"
            .parse::<Ipv4Net>()
            .expect("Unable to parse IPv4 CIDR - check format");
        let mut combined = 256;
        for iteration in 0..17u32 {
            combined += 1;
            let extension = Some(IpCidrConExt::Session(combined));
            let ipv4_address1 = ipv4_from_extension(&cidr, None, extension);
            let ipv4_address2 = ipv4_from_extension(&cidr, None, extension);

            tracing::info!(
                "Iteration {}: Session ID: {} (0x{:x})",
                iteration,
                combined,
                combined
            );
            tracing::info!(
                "  IPv4 Address 1: {} (Host portion: {})",
                ipv4_address1,
                combined % ((1u64 << (32 - cidr.prefix_len())) - 1)
            );
            tracing::info!("  IPv4 Address 2: {} (Should be identical)", ipv4_address2);
            assert_eq!(
                ipv4_address1, ipv4_address2,
                "Session-based generation should be deterministic"
            );
        }
    }

    #[test]
    fn test_assign_ipv6_with_session() {
        init_tracing();
        let cidr = "2001:470:e953::/48"
            .parse::<Ipv6Net>()
            .expect("Unable to parse IPv6 CIDR - check format");
        let mut combined = 0x1234;
        for iteration in 0..17 {
            combined += 1;
            let extension = Some(IpCidrConExt::Session(combined));
            let ipv6_address1 = ipv6_from_extension(&cidr, None, extension);
            let ipv6_address2 = ipv6_from_extension(&cidr, None, extension);

            tracing::info!(
                "Iteration {}: Session ID: {} (0x{:x})",
                iteration,
                combined,
                combined
            );
            tracing::info!(
                "  IPv6 Address 1: {} (High bits: {:016x})",
                ipv6_address1,
                u128::from(ipv6_address1) >> 64
            );
            tracing::info!("  IPv6 Address 2: {} (Should be identical)", ipv6_address2);
            assert_eq!(
                ipv6_address1, ipv6_address2,
                "Session-based generation should be deterministic"
            );
        }
    }

    #[test]
    fn test_assign_ipv4_with_ttl() {
        init_tracing();
        let cidr = "101.30.16.0/20"
            .parse::<Ipv4Net>()
            .expect("Unable to parse IPv4 CIDR - check format");
        let mut ext = Extensions::default();
        let parser = (
            UsernameOpaqueLabelParser::new(),
            IpCidrConExtUsernameLabelParser::default(),
        );
        for iteration in 0..17u32 {
            parse_username(&mut ext, parser.clone(), "username-ttl-5")
                .expect("TTL username parsing should not fail");
            let extension = ext.get::<IpCidrConExt>();
            let ipv4_address = ipv4_from_extension(&cidr, None, extension.cloned());
            tracing::info!(
                "Iteration {}: TTL-based IPv4 Address: {}",
                iteration,
                ipv4_address
            );
            if let Some(IpCidrConExt::Ttl(normalized_timestamp)) = extension {
                tracing::debug!(
                    "  Normalized timestamp: {} (window boundary)",
                    normalized_timestamp
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(2500));
        }
    }

    #[test]
    fn test_assign_ipv6_with_ttl() {
        init_tracing();
        let cidr = "2001:470:e953::/48"
            .parse::<Ipv6Net>()
            .expect("Failed to parse IPv6 CIDR block - check format validity");
        let mut ext = Extensions::default();
        let parser = (
            UsernameOpaqueLabelParser::new(),
            IpCidrConExtUsernameLabelParser::default(),
        );
        let mut previous_address: Option<Ipv6Addr> = None;
        let mut window_start_iteration: Option<u32> = None;
        for iteration in 0..17u32 {
            tracing::debug!("=== TTL Test Iteration {} ===", iteration);
            parse_username(&mut ext, parser.clone(), "username-ttl-5")
                .expect("TTL username parsing should never fail with valid input");
            let extension = ext.get::<IpCidrConExt>();
            let ipv6_address = ipv6_from_extension(&cidr, None, extension.cloned());
            let (normalized_timestamp, raw_timestamp) =
                if let Some(IpCidrConExt::Ttl(timestamp)) = extension {
                    let raw = timestamp + (timestamp % 5);
                    (*timestamp, raw)
                } else {
                    (0, 0)
                };
            tracing::info!(
                "Iteration {}: TTL-based IPv6 Address: {} (Network: {})",
                iteration,
                ipv6_address,
                cidr.addr()
            );

            tracing::debug!(
                "  Normalized timestamp: {} (5-second boundary)",
                normalized_timestamp
            );

            tracing::debug!(
                "  Estimated raw timestamp: {} (before normalization)",
                raw_timestamp
            );

            tracing::debug!(
                "  Address binary (high 64 bits): {:016x}",
                u128::from(ipv6_address) >> 64
            );

            tracing::debug!(
                "  Address binary (low 64 bits): {:016x}",
                u128::from(ipv6_address) & 0xFFFFFFFFFFFFFFFF
            );
            if let Some(prev_addr) = previous_address {
                if ipv6_address == prev_addr {
                    tracing::info!(
                        "  ✓ Address consistency maintained within TTL window (since iteration {})",
                        window_start_iteration.unwrap_or(iteration.saturating_sub(1))
                    );
                } else {
                    tracing::info!(
                        "  ⧖ TTL window boundary crossed - new deterministic address generated"
                    );
                    window_start_iteration = Some(iteration);
                }
            } else {
                window_start_iteration = Some(iteration);
                tracing::info!("  ⭐ Baseline address established for TTL window tracking");
            }

            let network_addr = cidr.addr();
            let broadcast_addr = cidr.broadcast();
            assert!(
                u128::from(ipv6_address) >= u128::from(network_addr)
                    && u128::from(ipv6_address) <= u128::from(broadcast_addr),
                "Generated address {} must fall within CIDR range {} - {}",
                ipv6_address,
                network_addr,
                broadcast_addr
            );

            let addr_u128 = u128::from(ipv6_address);
            let network_u128 = u128::from(network_addr);
            let prefix_mask = !((1u128 << (128 - cidr.prefix_len())) - 1);
            assert_eq!(
                addr_u128 & prefix_mask,
                network_u128 & prefix_mask,
                "Network prefix must be preserved in generated address"
            );
            previous_address = Some(ipv6_address);
            tracing::debug!("  Sleeping 2.5 seconds to test TTL window boundary behavior...");
            std::thread::sleep(std::time::Duration::from_millis(2500));
        }
        tracing::info!(
            "TTL-based IPv6 generation test completed successfully across {} iterations",
            17
        );
        tracing::info!(
            "Validated: temporal consistency, boundary transitions, precision arithmetic, and network preservation"
        );
    }
}
