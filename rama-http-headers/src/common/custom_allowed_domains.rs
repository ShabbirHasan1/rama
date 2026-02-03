use bitcode::{Decode, Encode};
use rama_net::address::Domain;
use serde_repr::{Deserialize_repr, Serialize_repr};

pub static STATICIPIN: Domain = Domain::from_static("staticip.in");
pub static IPIFYORG: Domain = Domain::from_static("ipify.org");
pub static IFCONFIGCO: Domain = Domain::from_static("ifconfig.co");
pub static IFCONFIGME: Domain = Domain::from_static("ifconfig.me");
pub static HTTPBINORG: Domain = Domain::from_static("httpbin.org");
pub static BEECEPTORCOM: Domain = Domain::from_static("beeceptor.com");

pub static ACAGARWALCOM: Domain = Domain::from_static("acagarwal.com");
pub static ALICEBLUEONLINECOM: Domain = Domain::from_static("aliceblueonline.com");
pub static ANGELBROKINGCOM: Domain = Domain::from_static("angelbroking.com");
pub static ANGELONEIN: Domain = Domain::from_static("angelone.in");
pub static ARHAMWEALTHCOM: Domain = Domain::from_static("arhamwealth.com");
pub static AXISDIRECTIN: Domain = Domain::from_static("axisdirect.in");
pub static BIGULCO: Domain = Domain::from_static("bigul.co");
pub static BVCPLCOM: Domain = Domain::from_static("bvcpl.com");
pub static CHOICEINDIACOM: Domain = Domain::from_static("choiceindia.com");
pub static COMPOSITEDGECOM: Domain = Domain::from_static("compositedge.com");
pub static DBONLINEIN: Domain = Domain::from_static("dbonline.in");
pub static DELTAEXCHANGE: Domain = Domain::from_static("deltaexchange.com");
pub static DHANCO: Domain = Domain::from_static("dhan.co");
pub static ENRICHMONEYIN: Domain = Domain::from_static("enrichmoney.in");
pub static FINDOCCOM: Domain = Domain::from_static("findoc.com");
pub static FIVEPAISACOM: Domain = Domain::from_static("5paisa.com");
pub static FLATTRADEIN: Domain = Domain::from_static("flattrade.in");
pub static FYERSIN: Domain = Domain::from_static("fyers.in");
pub static ICICIDIRECTCOM: Domain = Domain::from_static("icicidirect.com");
pub static IIFLCOM: Domain = Domain::from_static("iifl.com");
pub static INDIRATRADECOM: Domain = Domain::from_static("indiratrade.com");
pub static JAINAMIN: Domain = Domain::from_static("jainam.in");
pub static JMFINANCIALSERVICESIN: Domain = Domain::from_static("jmfinancialservices.in");
pub static JMFONLINEIN: Domain = Domain::from_static("jmfonline.in");
pub static KITETRADE: Domain = Domain::from_static("kite.trade");
pub static KOTAKSECURITIESCOM: Domain = Domain::from_static("kotaksecurities.com");
pub static MASTERTRUSTCOIN: Domain = Domain::from_static("mastertrust.co.in");
pub static MONEYSUKHCOM: Domain = Domain::from_static("moneysukh.com");
pub static MOTILALOSWALCOM: Domain = Domain::from_static("motilaloswal.com");
pub static MSTOCKCOM: Domain = Domain::from_static("mstock.com");
pub static MSTOCKTRADE: Domain = Domain::from_static("mstock.trade");
pub static MYNTIN: Domain = Domain::from_static("mynt.in");
pub static NUVAMAWEALTHCOM: Domain = Domain::from_static("nuvamawealth.com");
pub static PAYTMMONEYCOM: Domain = Domain::from_static("paytmmoney.com");
pub static SHAREKHANCOM: Domain = Domain::from_static("sharekhan.com");
pub static SHOONYACOM: Domain = Domain::from_static("shoonya.com");
pub static SMCTRADEONLINECOM: Domain = Domain::from_static("smctradeonline.com");
pub static STOXKARTCOM: Domain = Domain::from_static("stoxkart.com");
pub static SWASTIKACOIN: Domain = Domain::from_static("swastika.co.in");
pub static THEFIRSTOCKCOM: Domain = Domain::from_static("thefirstock.com");
pub static TRADEJINICOM: Domain = Domain::from_static("tradejini.com");
pub static TRADESMARTONLINEIN: Domain = Domain::from_static("tradesmartonline.in");
pub static UPSTOXCOM: Domain = Domain::from_static("upstox.com");
pub static WISDOMCAPITALIN: Domain = Domain::from_static("wisdomcapital.in");
pub static ZEBUETRADECOM: Domain = Domain::from_static("zebuetrade.com");
pub static ZERODHACOM: Domain = Domain::from_static("zerodha.com");

pub static ALLOWED_GENERAL_DOMAINS: [WhiteListedDomains; 6] =
    WhiteListedDomains::allowed_general_domains();

pub static ALLOWED_BROKER_DOMAINS: [WhiteListedDomains; 46] =
    WhiteListedDomains::allowed_broker_domains();

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize_repr,
    Deserialize_repr,
    Encode,
    Decode,
)]
#[repr(u8)]
pub enum WhiteListedDomains {
    StaticipIn,
    IpifyOrg,
    IfconfigCo,
    IfconfigMe,
    HttpbinOrg,
    BeeceptorCom,
    AcagarwalCom,
    AliceblueonlineCom,
    AngelbrokingCom,
    AngeloneIn,
    ArhamwealthCom,
    AxisdirectIn,
    BigulCo,
    BvcplCom,
    ChoiceindiaCom,
    CompositedgeCom,
    DbonlineIn,
    DeltaExchange,
    DhanCo,
    EnrichmoneyIn,
    FindocCom,
    FivePaisaCom,
    FlattradeIn,
    FyersIn,
    IcicidirectCom,
    IiflCom,
    IndiratradeCom,
    JainamIn,
    JmfinancialservicesIn,
    JmfonlineIn,
    KiteTrade,
    KotaksecuritiesCom,
    MastertrustCoIn,
    MoneysukhCom,
    MotilaloswalCom,
    MstockCom,
    MstockTrade,
    MyntIn,
    NuvamawealthCom,
    PaytmmoneyCom,
    SharekhanCom,
    ShoonyaCom,
    SmctradeonlineCom,
    StoxkartCom,
    SwastikaCoIn,
    ThefirstockCom,
    TradejiniCom,
    TradesmartonlineIn,
    UpstoxCom,
    WisdomcapitalIn,
    ZebuetradeCom,
    ZerodhaCom,
}

impl AsRef<str> for WhiteListedDomains {
    fn as_ref(&self) -> &'static str {
        match self {
            Self::StaticipIn => STATICIPIN.as_ref(),
            Self::IpifyOrg => IPIFYORG.as_ref(),
            Self::IfconfigCo => IFCONFIGCO.as_ref(),
            Self::IfconfigMe => IFCONFIGME.as_ref(),
            Self::HttpbinOrg => HTTPBINORG.as_ref(),
            Self::BeeceptorCom => BEECEPTORCOM.as_ref(),
            Self::AcagarwalCom => ACAGARWALCOM.as_ref(),
            Self::AliceblueonlineCom => ALICEBLUEONLINECOM.as_ref(),
            Self::AngelbrokingCom => ANGELBROKINGCOM.as_ref(),
            Self::AngeloneIn => ANGELONEIN.as_ref(),
            Self::ArhamwealthCom => ARHAMWEALTHCOM.as_ref(),
            Self::AxisdirectIn => AXISDIRECTIN.as_ref(),
            Self::BigulCo => BIGULCO.as_ref(),
            Self::BvcplCom => BVCPLCOM.as_ref(),
            Self::ChoiceindiaCom => CHOICEINDIACOM.as_ref(),
            Self::CompositedgeCom => COMPOSITEDGECOM.as_ref(),
            Self::DbonlineIn => DBONLINEIN.as_ref(),
            Self::DeltaExchange => DELTAEXCHANGE.as_ref(),
            Self::DhanCo => DHANCO.as_ref(),
            Self::EnrichmoneyIn => ENRICHMONEYIN.as_ref(),
            Self::FindocCom => FINDOCCOM.as_ref(),
            Self::FivePaisaCom => FIVEPAISACOM.as_ref(),
            Self::FlattradeIn => FLATTRADEIN.as_ref(),
            Self::FyersIn => FYERSIN.as_ref(),
            Self::IcicidirectCom => ICICIDIRECTCOM.as_ref(),
            Self::IiflCom => IIFLCOM.as_ref(),
            Self::IndiratradeCom => INDIRATRADECOM.as_ref(),
            Self::JainamIn => JAINAMIN.as_ref(),
            Self::JmfinancialservicesIn => JMFINANCIALSERVICESIN.as_ref(),
            Self::JmfonlineIn => JMFONLINEIN.as_ref(),
            Self::KiteTrade => KITETRADE.as_ref(),
            Self::KotaksecuritiesCom => KOTAKSECURITIESCOM.as_ref(),
            Self::MastertrustCoIn => MASTERTRUSTCOIN.as_ref(),
            Self::MoneysukhCom => MONEYSUKHCOM.as_ref(),
            Self::MotilaloswalCom => MOTILALOSWALCOM.as_ref(),
            Self::MstockCom => MSTOCKCOM.as_ref(),
            Self::MstockTrade => MSTOCKTRADE.as_ref(),
            Self::MyntIn => MYNTIN.as_ref(),
            Self::NuvamawealthCom => NUVAMAWEALTHCOM.as_ref(),
            Self::PaytmmoneyCom => PAYTMMONEYCOM.as_ref(),
            Self::SharekhanCom => SHAREKHANCOM.as_ref(),
            Self::ShoonyaCom => SHOONYACOM.as_ref(),
            Self::SmctradeonlineCom => SMCTRADEONLINECOM.as_ref(),
            Self::StoxkartCom => STOXKARTCOM.as_ref(),
            Self::SwastikaCoIn => SWASTIKACOIN.as_ref(),
            Self::ThefirstockCom => THEFIRSTOCKCOM.as_ref(),
            Self::TradejiniCom => TRADEJINICOM.as_ref(),
            Self::TradesmartonlineIn => TRADESMARTONLINEIN.as_ref(),
            Self::UpstoxCom => UPSTOXCOM.as_ref(),
            Self::WisdomcapitalIn => WISDOMCAPITALIN.as_ref(),
            Self::ZebuetradeCom => ZEBUETRADECOM.as_ref(),
            Self::ZerodhaCom => ZERODHACOM.as_ref(),
        }
    }
}

impl WhiteListedDomains {
    /// Returns a reference to the domain of this [`WhiteListedRootDomain`].
    #[must_use]
    pub fn as_domain(&self) -> &Domain {
        match self {
            Self::StaticipIn => &STATICIPIN,
            Self::IpifyOrg => &IPIFYORG,
            Self::IfconfigCo => &IFCONFIGCO,
            Self::IfconfigMe => &IFCONFIGME,
            Self::HttpbinOrg => &HTTPBINORG,
            Self::BeeceptorCom => &BEECEPTORCOM,
            Self::AcagarwalCom => &ACAGARWALCOM,
            Self::AliceblueonlineCom => &ALICEBLUEONLINECOM,
            Self::AngelbrokingCom => &ANGELBROKINGCOM,
            Self::AngeloneIn => &ANGELONEIN,
            Self::ArhamwealthCom => &ARHAMWEALTHCOM,
            Self::AxisdirectIn => &AXISDIRECTIN,
            Self::BigulCo => &BIGULCO,
            Self::BvcplCom => &BVCPLCOM,
            Self::ChoiceindiaCom => &CHOICEINDIACOM,
            Self::CompositedgeCom => &COMPOSITEDGECOM,
            Self::DbonlineIn => &DBONLINEIN,
            Self::DeltaExchange => &DELTAEXCHANGE,
            Self::DhanCo => &DHANCO,
            Self::EnrichmoneyIn => &ENRICHMONEYIN,
            Self::FindocCom => &FINDOCCOM,
            Self::FivePaisaCom => &FIVEPAISACOM,
            Self::FlattradeIn => &FLATTRADEIN,
            Self::FyersIn => &FYERSIN,
            Self::IcicidirectCom => &ICICIDIRECTCOM,
            Self::IiflCom => &IIFLCOM,
            Self::IndiratradeCom => &INDIRATRADECOM,
            Self::JainamIn => &JAINAMIN,
            Self::JmfinancialservicesIn => &JMFINANCIALSERVICESIN,
            Self::JmfonlineIn => &JMFONLINEIN,
            Self::KiteTrade => &KITETRADE,
            Self::KotaksecuritiesCom => &KOTAKSECURITIESCOM,
            Self::MastertrustCoIn => &MASTERTRUSTCOIN,
            Self::MoneysukhCom => &MONEYSUKHCOM,
            Self::MotilaloswalCom => &MOTILALOSWALCOM,
            Self::MstockCom => &MSTOCKCOM,
            Self::MstockTrade => &MSTOCKTRADE,
            Self::MyntIn => &MYNTIN,
            Self::NuvamawealthCom => &NUVAMAWEALTHCOM,
            Self::PaytmmoneyCom => &PAYTMMONEYCOM,
            Self::SharekhanCom => &SHAREKHANCOM,
            Self::ShoonyaCom => &SHOONYACOM,
            Self::SmctradeonlineCom => &SMCTRADEONLINECOM,
            Self::StoxkartCom => &STOXKARTCOM,
            Self::SwastikaCoIn => &SWASTIKACOIN,
            Self::ThefirstockCom => &THEFIRSTOCKCOM,
            Self::TradejiniCom => &TRADEJINICOM,
            Self::TradesmartonlineIn => &TRADESMARTONLINEIN,
            Self::UpstoxCom => &UPSTOXCOM,
            Self::WisdomcapitalIn => &WISDOMCAPITALIN,
            Self::ZebuetradeCom => &ZEBUETRADECOM,
            Self::ZerodhaCom => &ZERODHACOM,
        }
    }

    pub fn is_wildcard_domain(&self) -> bool {
        matches!(self, Self::StaticipIn)
    }

    pub const fn allowed_general_domains() -> [Self; 6] {
        [
            Self::StaticipIn,
            Self::IpifyOrg,
            Self::IfconfigCo,
            Self::IfconfigMe,
            Self::HttpbinOrg,
            Self::BeeceptorCom,
        ]
    }

    pub const fn allowed_broker_domains() -> [Self; 46] {
        [
            Self::AcagarwalCom,
            Self::AliceblueonlineCom,
            Self::AngelbrokingCom,
            Self::AngeloneIn,
            Self::ArhamwealthCom,
            Self::AxisdirectIn,
            Self::BigulCo,
            Self::BvcplCom,
            Self::ChoiceindiaCom,
            Self::CompositedgeCom,
            Self::DbonlineIn,
            Self::DeltaExchange,
            Self::DhanCo,
            Self::EnrichmoneyIn,
            Self::FindocCom,
            Self::FivePaisaCom,
            Self::FlattradeIn,
            Self::FyersIn,
            Self::IcicidirectCom,
            Self::IiflCom,
            Self::IndiratradeCom,
            Self::JainamIn,
            Self::JmfinancialservicesIn,
            Self::JmfonlineIn,
            Self::KiteTrade,
            Self::KotaksecuritiesCom,
            Self::MastertrustCoIn,
            Self::MoneysukhCom,
            Self::MotilaloswalCom,
            Self::MstockCom,
            Self::MstockTrade,
            Self::MyntIn,
            Self::NuvamawealthCom,
            Self::PaytmmoneyCom,
            Self::SharekhanCom,
            Self::ShoonyaCom,
            Self::SmctradeonlineCom,
            Self::StoxkartCom,
            Self::SwastikaCoIn,
            Self::ThefirstockCom,
            Self::TradejiniCom,
            Self::TradesmartonlineIn,
            Self::UpstoxCom,
            Self::WisdomcapitalIn,
            Self::ZebuetradeCom,
            Self::ZerodhaCom,
        ]
    }

    pub fn is_allowed_general_domain(domain: &Domain) -> bool {
        ALLOWED_GENERAL_DOMAINS
            .iter()
            .any(|d| d.is_parent_of(domain))
    }

    pub fn is_allowed_broker_domain(domain: &Domain) -> bool {
        ALLOWED_BROKER_DOMAINS
            .iter()
            .any(|d| d.is_parent_of(domain))
    }

    pub fn is_parent_of(&self, domain: &Domain) -> bool {
        self.as_domain().is_parent_of(domain)
    }
}

#[cfg(test)]
mod test {
    use super::WhiteListedDomains::*;
    use super::*;

    #[test]
    fn test_is_wildcard_domain() {
        assert!(StaticipIn.is_wildcard_domain());
        assert!(!MyntIn.is_wildcard_domain());
    }

    #[test]
    fn test_is_general_domain() {
        assert!(IpifyOrg.is_general_domain(&IPIFYORG));
        assert!(IfconfigCo.is_general_domain(&IFCONFIGCO));
        assert!(IfconfigMe.is_general_domain(&IFCONFIGME));
        assert!(HttpbinOrg.is_general_domain(&HTTPBINORG));
        assert!(BeeceptorCom.is_general_domain(&BEECEPTORCOM));
        assert!(!MyntIn.is_general_domain(&MYNTIN));
    }

    #[test]
    fn test_is_parent_of() {
        assert!(IpifyOrg.is_parent_of(&Domain::from_static("api.ipify.org")));
        assert!(IfconfigCo.is_parent_of(&Domain::from_static("ip.ifconfig.co")));
        assert!(IfconfigMe.is_parent_of(&Domain::from_static("ip.ifconfig.me")));
        assert!(HttpbinOrg.is_parent_of(&Domain::from_static("api.httpbin.org")));
        assert!(BeeceptorCom.is_parent_of(&Domain::from_static("echo.free.beeceptor.com")));
    }

    #[test]
    fn test_is_subdomain_of() {
        assert!(Domain::from_static("api.kite.trade").is_sub_of(&KiteTrade.as_domain()));
        assert!(Domain::from_static("kite.zerodha.com").is_sub_of(&ZerodhaCom.as_domain()));
        assert!(Domain::from_static("api.dhan.co").is_sub_of(&DhanCo.as_domain()));
        assert!(Domain::from_static("trade.fyers.in").is_sub_of(&FyersIn.as_domain()));
        assert!(Domain::from_static("ttblaze.iifl.com").is_sub_of(&IiflCom.as_domain()));
    }
}
