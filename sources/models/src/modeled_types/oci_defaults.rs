use serde::{Deserialize, Deserializer, Serialize, Serializer};
// Just need serde's Error in scope to get its trait methods
use super::error;
use serde::de::Error as _;
use snafu::{ensure, ResultExt};
use std::borrow::Borrow;
use std::convert::TryFrom;
use std::fmt;
use std::net::IpAddr;
use std::ops::Deref;

// Declare constant values usable by any type
const RESOURCE_LIMITS_MAX_OPEN_FILES_HARD: i32 = 1048576;
const RESOURCE_LIMITS_MAX_OPEN_FILES_SOFT: i32 = 65536;

/// OciDefaultsCapabilities is the percent of disk usage after which image
/// garbage collection is always run. The percent is calculated by dividing this
/// field value by 100, so this field must be between 0 and 100, inclusive. When
/// specified, the value must be greater than imageGCLowThresholdPercent.
/// Default: 85
/// https://kubernetes.io/docs/reference/config-api/kubelet-config.v1beta1/

#[serde(rename_all(serialize = "kebab-case", deserialize = "camelCase"))]
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum OciDefaultsCapability {
    AuditControl,
    AuditRead,
    AuditWrite,
    BlockSuspend,
    Bpf,
    CheckpointRestore,
    Chown,
    DacOverride,
    DacReadSearch,
    Fowner,
    Fsetid,
    IpcLock,
    IpcOwner,
    Kill,
    Lease,
    LinuxImmutable,
    MacAdmin,
    MacOverride,
    Mknod,
    NetAdmin,
    NetBindService,
    NetBroadcast,
    NetRaw,
    Perfmon,
    Setgid,
    Setfcap,
    Setpcap,
    Setuid,
    SysAdmin,
    SysBoot,
    SysChroot,
    SysModule,
    SysNice,
    SysPacct,
    SysPtrace,
    SysRawio,
    SysResource,
    SysTime,
    SysTtyConfig,
    Syslog,
    WakeAlarm,
}

/// OciDefaultsCapabilities is the percent of disk usage after which image
/// garbage collection is always run. The percent is calculated by dividing this
/// field value by 100, so this field must be between 0 and 100, inclusive. When
/// specified, the value must be greater than imageGCLowThresholdPercent.
/// Default: 85
/// https://kubernetes.io/docs/reference/config-api/kubelet-config.v1beta1/

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct OciDefaultsCapabilities {
    inner: String,
}

impl TryFrom<&str> for OciDefaultsCapabilities {
    type Error = error::Error;

    fn try_from(input: &str) -> Result<Self, Self::Error> {
        let parsed_input: i32 = input
            .parse::<i32>()
            .context(error::ParseIntSnafu { input })?;
        ensure!(
            !input.is_empty(),
            error::InvalidOciDefaultsSnafu {
                default_value_name: "capabilities",
                provided_value: input,
                validity_rule: "must not be empty",
            }
        );

        Ok(OciDefaultsCapabilities {
            inner: input.to_owned(),
        })
    }
}
string_impls_for!(OciDefaultsCapabilities, "OciDefaultsCapabilities");

#[cfg(test)]
mod test_image_gc_high_threshold_percent {
    use super::OciDefaultsCapabilities;
    use std::convert::TryFrom;

    // test 1: good values should succeed
    #[test]
    fn image_gc_high_threshold_percent_between_0_and_100_inclusive() {
        for ok in &["0", "1", "99", "100"] {
            OciDefaultsCapabilities::try_from(*ok).unwrap();
        }
    }

    // test 2: values too low should return Errors
    #[test]
    fn image_gc_high_threshold_percent_less_than_0_fails() {
        OciDefaultsCapabilities::try_from("-1").unwrap_err();
    }

    // test 3: values too high should return Errors
    #[test]
    fn image_gc_high_threshold_percent_greater_than_100_fails() {
        OciDefaultsCapabilities::try_from("101").unwrap_err();
    }
}

// =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=

/// OciDefaultsResourceLimits is the percent of disk usage before which image
/// garbage collection is never run. Lowest disk usage to garbage collect to.
/// The percent is calculated by dividing this field value by 100, so the field
/// value must be between 0 and 100, inclusive. When specified, the value must
/// be less than imageGCHighThresholdPercent.
/// Default: 80
/// https://kubernetes.io/docs/reference/config-api/kubelet-config.v1beta1/

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct OciDefaultsResourceLimit {
    inner: String,
}

impl TryFrom<&str> for OciDefaultsResourceLimit {
    type Error = error::Error;

    fn try_from(input: &str) -> Result<Self, Self::Error> {
        let parsed_input: i32 = input
            .parse::<i32>()
            .context(error::ParseIntSnafu { input })?;
        ensure!(
            !input.is_empty(),
            error::InvalidOciDefaultsSnafu {
                default_value_name: "resource-limits",
                provided_value: input,
                validity_rule: "must not be empty",
            }
        );

        Ok(OciDefaultsResourceLimit {
            inner: input.to_owned(),
        })
    }
}
string_impls_for!(OciDefaultsResourceLimit, "OciDefaultsResourceLimit");

#[cfg(test)]
mod test_image_gc_low_threshold_percent {
    use super::OciDefaultsResourceLimits;
    use std::convert::TryFrom;

    // test 1: good values should succeed
    #[test]
    fn image_gc_low_threshold_percent_between_0_and_100_inclusive() {
        for ok in &["0", "1", "99", "100"] {
            OciDefaultsResourceLimits::try_from(*ok).unwrap();
        }
    }

    // test 2: values too low should return Errors
    #[test]
    fn image_gc_low_threshold_percent_less_than_0_fails() {
        OciDefaultsResourceLimits::try_from("-1").unwrap_err();
    }

    // test 3: values too high should return Errors
    #[test]
    fn image_gc_low_threshold_percent_greater_than_100_fails() {
        OciDefaultsResourceLimits::try_from("101").unwrap_err();
    }
}

// =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=

/// KubernetesClusterDnsIp represents the --cluster-dns settings for kubelet.
///
/// This model allows the value to be either a list of IPs, or a single IP string
/// for backwards compatibility.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum KubernetesClusterDnsIpz {
    Scalar(IpAddr),
    Vector(Vec<IpAddr>),
}

impl KubernetesClusterDnsIpz {
    pub fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = &'a IpAddr> + 'a> {
        match self {
            Self::Scalar(inner) => Box::new(std::iter::once(inner)),
            Self::Vector(inner) => Box::new(inner.iter()),
        }
    }

    pub fn into_iter(self) -> impl Iterator<Item = IpAddr> {
        match self {
            Self::Scalar(inner) => vec![inner],
            Self::Vector(inner) => inner,
        }
        .into_iter()
    }
}

#[cfg(test)]
mod test_cluster_dns_ip {
    use super::KubernetesClusterDnsIpz;
    use std::net::IpAddr;
    use std::str::FromStr;

    #[test]
    fn test_parse_cluster_dns_ip_from_str() {
        assert_eq!(
            serde_json::from_str::<KubernetesClusterDnsIpz>(r#""127.0.0.1""#).unwrap(),
            KubernetesClusterDnsIpz::Scalar(IpAddr::from_str("127.0.0.1").unwrap())
        );
        assert_eq!(
            serde_json::from_str::<KubernetesClusterDnsIpz>(r#""::1""#).unwrap(),
            KubernetesClusterDnsIpz::Scalar(IpAddr::from_str("::1").unwrap())
        );
    }

    #[test]
    fn test_parse_cluster_dns_ip_from_list() {
        assert_eq!(
            serde_json::from_str::<KubernetesClusterDnsIpz>(r#"[]"#).unwrap(),
            KubernetesClusterDnsIpz::Vector(vec![])
        );
        assert_eq!(
            serde_json::from_str::<KubernetesClusterDnsIpz>(r#"["127.0.0.1", "::1"]"#).unwrap(),
            KubernetesClusterDnsIpz::Vector(vec![
                IpAddr::from_str("127.0.0.1").unwrap(),
                IpAddr::from_str("::1").unwrap()
            ])
        );
    }

    #[test]
    fn test_iter_cluster_dns_ips() {
        assert_eq!(
            KubernetesClusterDnsIpz::Vector(vec![])
                .iter()
                .collect::<Vec<&IpAddr>>(),
            Vec::<&IpAddr>::new(),
        );

        assert_eq!(
            KubernetesClusterDnsIpz::Vector(vec![
                IpAddr::from_str("127.0.0.1").unwrap(),
                IpAddr::from_str("::1").unwrap()
            ])
            .iter()
            .collect::<Vec<&IpAddr>>(),
            vec![
                &IpAddr::from_str("127.0.0.1").unwrap(),
                &IpAddr::from_str("::1").unwrap()
            ]
        );

        assert_eq!(
            KubernetesClusterDnsIpz::Scalar(IpAddr::from_str("127.0.0.1").unwrap())
                .iter()
                .collect::<Vec<&IpAddr>>(),
            vec![&IpAddr::from_str("127.0.0.1").unwrap()],
        );
    }

    #[test]
    fn test_first_cluster_dns_ips() {
        assert_eq!(KubernetesClusterDnsIpz::Vector(vec![]).iter().next(), None);

        assert_eq!(
            KubernetesClusterDnsIpz::Vector(vec![
                IpAddr::from_str("127.0.0.1").unwrap(),
                IpAddr::from_str("::1").unwrap()
            ])
            .iter()
            .next(),
            Some(&IpAddr::from_str("127.0.0.1").unwrap())
        );

        assert_eq!(
            KubernetesClusterDnsIpz::Scalar(IpAddr::from_str("127.0.0.1").unwrap())
                .iter()
                .next(),
            Some(&IpAddr::from_str("127.0.0.1").unwrap())
        );
    }
}
