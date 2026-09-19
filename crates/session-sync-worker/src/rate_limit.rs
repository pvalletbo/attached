use std::net::{IpAddr, Ipv6Addr};

use worker::{Env, Request};

const ACCOUNT_CREATION_BINDING: &str = "ACCOUNT_CREATION_RATE_LIMITER";
// Keep this conservative retry delay aligned with the period in wrangler.toml.
pub(crate) const RETRY_AFTER_SECONDS: &str = "60";

pub(crate) async fn allow_account_creation(request: &Request, env: &Env) -> worker::Result<bool> {
    // Cloudflare sets this header at ingress. Do not use client-controlled
    // Forwarded/X-Forwarded-For headers or fall back to an unthrottled path.
    let ip = request.headers().get("cf-connecting-ip")?;
    let key = account_creation_key(ip.as_deref()).ok_or_else(|| {
        worker::Error::RustError("account creation client address unavailable".to_owned())
    })?;
    Ok(env
        .rate_limiter(ACCOUNT_CREATION_BINDING)?
        .limit(key)
        .await?
        .success)
}

fn account_creation_key(ip: Option<&str>) -> Option<String> {
    let ip = ip?.parse::<IpAddr>().ok()?.to_canonical();
    let network = match ip {
        IpAddr::V4(ip) => ip.to_string(),
        // Privacy addresses within one IPv6 /64 must share a budget, rather
        // than allowing a caller to evade it by rotating interface identifiers.
        IpAddr::V6(ip) => Ipv6Addr::from(u128::from(ip) & (u128::MAX << 64)).to_string(),
    };
    Some(format!("account-create:v1:{network}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_addresses_have_independent_budgets() {
        assert_eq!(
            account_creation_key(Some("192.0.2.1")).as_deref(),
            Some("account-create:v1:192.0.2.1")
        );
        assert_ne!(
            account_creation_key(Some("192.0.2.1")),
            account_creation_key(Some("192.0.2.2"))
        );
    }

    #[test]
    fn ipv6_privacy_addresses_share_a_canonical_prefix_budget() {
        let key = account_creation_key(Some("2001:db8:1234:5678::1"));
        assert_eq!(
            key.as_deref(),
            Some("account-create:v1:2001:db8:1234:5678::")
        );
        assert_eq!(
            key,
            account_creation_key(Some("2001:0DB8:1234:5678:FFFF:FFFF:FFFF:FFFF"))
        );
        assert_ne!(key, account_creation_key(Some("2001:db8:1234:5679::1")));
    }

    #[test]
    fn ipv4_mapped_ipv6_cannot_bypass_the_ipv4_budget() {
        assert_eq!(
            account_creation_key(Some("::ffff:c000:201")),
            account_creation_key(Some("192.0.2.1"))
        );
    }

    #[test]
    fn missing_or_malformed_addresses_fail_closed() {
        assert_eq!(account_creation_key(None), None);
        for ip in [
            "",
            "unknown",
            "192.0.2.1, 192.0.2.2",
            "192.0.2.1:443",
            " 192.0.2.1",
            "[2001:db8::1]",
            "fe80::1%eth0",
        ] {
            assert_eq!(account_creation_key(Some(ip)), None, "{ip}");
        }
    }
}
