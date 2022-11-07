#![deny(rust_2018_idioms)]

use migration_helpers::common_migrations;
use migration_helpers::{migrate, Result};
use std::process;

/// We added new settings for configuring the default OCI runtime spec,
/// `settings.oci-defaults`, which will initially contain
/// `settings.oci-defaults.capabilities` and
/// `settings.oci-defaults.resource-limits`
fn run() -> Result<()> {
    migrate(common_migrations::AddPrefixesMigration(vec![
        "settings.oci-defaults",
    ]))
}

// Returning a Result from main makes it print a Debug representation of the error, but with Snafu
// we have nice Display representations of the error, so we wrap "main" (run) and print any error.
// https://github.com/shepmaster/snafu/issues/110
fn main() {
    if let Err(e) = run() {
        eprintln!("{}", e);
        process::exit(1);
    }
}
