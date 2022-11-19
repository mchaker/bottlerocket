use serde::{Deserialize, Serialize};
use serde_plain::{derive_display_from_serialize, derive_fromstr_from_deserialize};

/// OciDefaultsCapabilities is the percent of disk usage after which image
/// garbage collection is always run. The percent is calculated by dividing this
/// field value by 100, so this field must be between 0 and 100, inclusive. When
/// specified, the value must be greater than imageGCLowThresholdPercent.
/// Default: 85
/// https://kubernetes.io/docs/reference/config-api/kubelet-config.v1beta1/

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
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

derive_display_from_serialize!(OciDefaultsCapability);
derive_fromstr_from_deserialize!(OciDefaultsCapability);

impl OciDefaultsCapability {
    /// Converts from Bottlerocket's kabob-case name into the Linux capability name, e.g. turns
    /// `wake-alarm` into `CAP_WAKE_ALARM`.
    pub fn as_linux_string(&self) -> String {
        format!("CAP_{}", self.to_string().to_uppercase().replace('-', "_"))
    }
}

#[cfg(test)]
mod oci_defaults_capabilities {
    use super::*;

    fn check_capability_strings(cap: OciDefaultsCapability, bottlerocket: &str, linux: &str) {
        let actual_bottlerocket = cap.to_string();
        let actual_linux = cap.as_linux_string();
        assert_eq!(bottlerocket, actual_bottlerocket);
        assert_eq!(linux, actual_linux);
    }

    #[test]
    fn linux_capability_strings() {
        check_capability_strings(
            OciDefaultsCapability::AuditControl,
            "audit-control",
            "CAP_AUDIT_CONTROL",
        );

        check_capability_strings(
            OciDefaultsCapability::SysPacct,
            "sys-pacct",
            "CAP_SYS_PACCT",
        );

        check_capability_strings(OciDefaultsCapability::Mknod, "mknod", "CAP_MKNOD");
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

// // TODO - use an enum?
// #[derive(Debug, Clone, Eq, PartialEq, Hash)]
// pub struct OciDefaultsResourceLimit {
//     inner: String,
// }

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OciDefaultsResourceLimitType {
    MaxOpenFiles,
}

impl OciDefaultsResourceLimitType {
    pub fn as_linux_string(&self) -> &'static str {
        match self {
            OciDefaultsResourceLimitType::MaxOpenFiles => "RLIMIT_NOFILE",
        }
    }
}
