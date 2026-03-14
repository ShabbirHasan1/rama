use serde_repr::{Deserialize_repr, Serialize_repr};
use std::net::{IpAddr, Ipv4Addr};

pub static JIANAM: IpAddr = IpAddr::V4(Ipv4Addr::new(103, 217, 67, 124));
pub static SYMPHONYXTSDEVELOPER: IpAddr = IpAddr::V4(Ipv4Addr::new(160, 30, 125, 84));

pub static ALLOWED_BROKER_IPS: [WhiteListedIps; 2] = WhiteListedIps::allowed_broker_ips();

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize_repr, Deserialize_repr,
)]
#[repr(u8)]
pub enum WhiteListedIps {
    Jianam,
    SymphonyXtsDeveloper,
}

impl AsRef<IpAddr> for WhiteListedIps {
    fn as_ref(&self) -> &'static IpAddr {
        match self {
            Self::Jianam => &JIANAM,
            Self::SymphonyXtsDeveloper => &SYMPHONYXTSDEVELOPER,
        }
    }
}

impl WhiteListedIps {
    pub const fn allowed_broker_ips() -> [Self; 2] {
        [Self::Jianam, Self::SymphonyXtsDeveloper]
    }

    #[inline]
    pub fn is_allowed_broker_ips(ip_addr: &IpAddr) -> bool {
        ALLOWED_BROKER_IPS.iter().any(|d| d.is_equal_to(ip_addr))
    }

    #[inline(always)]
    pub fn is_equal_to(&self, ip_addr: &IpAddr) -> bool {
        self.as_ref() == ip_addr
    }
}
