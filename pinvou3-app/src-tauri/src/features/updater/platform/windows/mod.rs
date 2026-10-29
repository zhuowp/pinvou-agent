mod startup_error;
pub(in crate::features::updater) use startup_error::show_startup_admission_failure;

#[cfg(all(
    target_arch = "x86_64",
    not(any(feature = "upgrade-host-lab", feature = "upgrade-host-production"))
))]
pub(in crate::features::updater) mod manual;
