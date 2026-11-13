//! `mimid-seed`: gives local users of a mimid provider a client and
//! KeyPackages, so that a peer's protocol-07 §5.2 keyMaterial request for
//! them succeeds (bead mimid-1wgh.46.10).
//!
//! mimid's JMAP surface cannot upload KeyPackages yet, so without this tool
//! no local user has a client and keyMaterial answers `noConsent` (decision
//! mimid-1wgh.7.9). Consent is implicit allow (`consent::allows`), so once a
//! user has KeyPackages any well-formed request is served.
//!
//! Usage:
//!
//! ```text
//! mimid-seed --config <mimid config.toml> --users alice,carol,dave
//!            [--count N] [--state-dir DIR] [--valid-through YYYY-MM-DD]
//! ```
//!
//! For each name the user is `mimi://<domain>/u/<name>`, with the domain
//! and database path taken from the mimid config. The tool:
//!
//! 1. mints one client [`Identity`] for the user, or reloads the one it
//!    minted before from `--state-dir`;
//! 2. creates the user's JMAP account if there is none (see below);
//! 3. tops the client up to `N` (default 20) unexpired one-time KeyPackages
//!    and one last-resort KeyPackage, each stored through
//!    [`KeyPackages::upload_key_package`], the validated upload path.
//!
//! Rerunning tops up rather than duplicating: the client is reloaded from
//! `--state-dir`, and only the missing KeyPackages are minted. A user whose
//! database already has clients but who has no state in `--state-dir` is
//! refused, since minting a second client would leave the first one's
//! private keys unaccounted for.
//!
//! The private state (the client's signature key and each KeyPackage's
//! private keys) is kept by [`mimi_mls::Store`] in
//! `<state-dir>/<name>/mls.sqlite`, next to `identity.json`, which holds the
//! public values [`Identity::load`] needs. A later tool can reload the
//! identity from these files and process a Welcome as the user. No private
//! key is ever printed.
//!
//! The JMAP account is created because the store models one JMAP account
//! per local user (`jmap_account`), and the JMAP surface keys everything on
//! it; keyMaterial itself does not read it. No bearer token is issued: a
//! token is a secret and the JMAP surface has nothing yet for a seeded user
//! to do.
//!
//! It is safe to run while mimid runs on the same database: [`Store::open`]
//! uses WAL with a 5 s busy timeout, uploads take SQLite's write lock with
//! `BEGIN IMMEDIATE`, and keyMaterial reads the KeyPackage tables on every
//! request. The tool refuses to apply migrations, so the database must
//! already be at exactly this build's mimid revision, and it refuses to
//! run as a user other than the database file's owner, so it cannot leave
//! `-wal` or `-shm` files mimid cannot open.
//!
//! # Limitations
//!
//! - The KeyPackages have OpenMLS's default lifetime (one hour in the past
//!   to 84 days ahead; see `mimi_mls`), which this tool cannot change. It
//!   checks that each one is valid through the end of `--valid-through`
//!   (default 2026-11-17, UTC) and stops otherwise.
//! - [`mimid_server::follower::relay::LocalUser::authenticated`] is meant
//!   for the JMAP layer and tests; this tool uses it as an operator acting
//!   for the user, with access to the database file as its only check.
//! - The state files are protected only by their modes (0700 directories,
//!   0600 files). They hold private keys in the clear.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fs::{DirBuilder, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use anyhow::{Context, anyhow, bail, ensure};
use mimi_mls::tls_codec::Deserialize;
use mimi_mls::wire::KeyPackage;
use mimi_mls::{Identity, KeyPackageKind};
use mimid_server::config::{Config, Domain};
use mimid_server::follower::key_packages::{KeyPackageEntry, KeyPackages, client_uri};
use mimid_server::follower::relay::LocalUser;
use mimid_server::hub::{Clock, SystemClock};
use mimid_server::store::{JmapStoreError, Store};
use serde::Serialize;
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::{ConnectOptions, Connection};

/// One-time KeyPackages per client when `--count` is not given.
const DEFAULT_COUNT: usize = 20;

/// The last day (UTC) the KeyPackages must cover when `--valid-through` is
/// not given: the last day of the IETF 127 hackathon table.
const DEFAULT_VALID_THROUGH: &str = "2026-11-17";

/// Permission bits a state directory or file must not have.
const FORBIDDEN_MODE_BITS: u32 = 0o077;

/// The public half of a seeded client, written next to its MLS store.
#[derive(Debug, Serialize, serde::Deserialize)]
struct IdentityFile {
    /// The user URI, which is the BasicCredential identity.
    user_uri: String,
    /// The client URI mimid derives from the signature key.
    client_uri: String,
    /// The Ed25519 signature public key, lowercase hex.
    signature_public_key: String,
}

/// Parsed command line.
#[derive(Debug)]
struct Args {
    config: PathBuf,
    users: Vec<String>,
    count: usize,
    state_dir: Option<PathBuf>,
    valid_through: String,
}

const USAGE: &str = "usage: mimid-seed --config <mimid config.toml> --users alice,carol,dave \
                     [--count N] [--state-dir DIR] [--valid-through YYYY-MM-DD]";

fn parse_args() -> anyhow::Result<Args> {
    let mut config = None;
    let mut users = None;
    let mut count = DEFAULT_COUNT;
    let mut state_dir = None;
    let mut valid_through = DEFAULT_VALID_THROUGH.to_owned();
    let mut args = std::env::args_os().skip(1);
    while let Some(flag) = args.next() {
        let flag = flag
            .into_string()
            .map_err(|_| anyhow!("non-UTF-8 argument\n{USAGE}"))?;
        if flag == "--help" || flag == "-h" {
            println!("{USAGE}");
            std::process::exit(0);
        }
        let value = args
            .next()
            .ok_or_else(|| anyhow!("{flag} needs a value\n{USAGE}"))?;
        let text = || {
            value
                .to_str()
                .map(str::to_owned)
                .ok_or_else(|| anyhow!("{flag}: non-UTF-8 value"))
        };
        match flag.as_str() {
            "--config" => config = Some(PathBuf::from(&value)),
            "--state-dir" => state_dir = Some(PathBuf::from(&value)),
            "--users" => users = Some(text()?),
            "--count" => {
                count = text()?
                    .parse()
                    .with_context(|| format!("--count {value:?} is not a number"))?;
            }
            "--valid-through" => valid_through = text()?,
            _ => bail!("unknown argument {flag}\n{USAGE}"),
        }
    }
    let config = config.ok_or_else(|| anyhow!("--config is required\n{USAGE}"))?;
    let users = users.ok_or_else(|| anyhow!("--users is required\n{USAGE}"))?;
    let mut seen = BTreeSet::new();
    let users: Vec<String> = users
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect();
    ensure!(!users.is_empty(), "--users names no user");
    for name in &users {
        // A conservative alphabet: the name is a URI path segment and a
        // directory name.
        ensure!(
            name.len() <= 64
                && name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
                && !name.starts_with('.'),
            "user name {name:?} must be 1 to 64 of a-z 0-9 . _ - and not start with '.'"
        );
        ensure!(seen.insert(name.clone()), "user {name:?} is listed twice");
    }
    ensure!(count >= 1, "--count must be at least 1");
    Ok(Args {
        config,
        users,
        count,
        state_dir,
        valid_through,
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = parse_args()?;
    let config =
        Config::load(&args.config).with_context(|| format!("loading {}", args.config.display()))?;
    let domain = config.domain.clone();
    let database = config.database.clone();
    let state_dir = args.state_dir.clone().unwrap_or_else(|| {
        let mut name = database.clone().into_os_string();
        name.push(".seed-state");
        PathBuf::from(name)
    });
    let required_until = end_of_day(&args.valid_through)?;
    let max = usize::try_from(config.max_key_packages).unwrap_or(usize::MAX);
    ensure!(
        args.count < max,
        "--count {} plus the last-resort KeyPackage exceeds max_key_packages = {max}",
        args.count
    );

    check_database(&database).await?;
    let store = Store::open(&database, &domain)
        .await
        .with_context(|| format!("opening database {}", database.display()))?;
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let key_packages = KeyPackages::new(store.clone(), domain.clone(), Arc::clone(&clock));
    private_dir(&state_dir)?;

    println!(
        "mimid-seed: domain {domain}, database {}",
        database.display()
    );
    println!(
        "mimid-seed: private state in {} (never printed)",
        state_dir.display()
    );
    let mut failed = false;
    for name in &args.users {
        let seeded = seed_user(
            &store,
            &key_packages,
            &domain,
            name,
            &state_dir,
            args.count,
            required_until,
            clock.as_ref(),
        )
        .await;
        if let Err(error) = seeded {
            failed = true;
            eprintln!("mimid-seed: {name}: FAILED: {error:#}");
        }
    }
    store.close().await;
    if failed {
        bail!("some users were not seeded");
    }
    Ok(())
}

/// Seeds one user and prints its summary.
#[allow(clippy::too_many_arguments)]
async fn seed_user(
    store: &Store,
    key_packages: &KeyPackages,
    domain: &Domain,
    name: &str,
    state_dir: &Path,
    count: usize,
    required_until: u64,
    clock: &dyn Clock,
) -> anyhow::Result<()> {
    let user_uri = format!("mimi://{domain}/u/{name}");
    let user = LocalUser::authenticated(domain, &user_uri)
        .map_err(|_| anyhow!("{user_uri} is not a user URI of {domain}"))?;
    let dir = state_dir.join(name);
    let identity_path = dir.join("identity.json");

    let (identity, minted) = if identity_path.exists() {
        (load_identity(&dir, &user_uri, domain)?, false)
    } else {
        let clients = store.clients_of_user(&user_uri).await?;
        if !clients.is_empty() {
            bail!(
                "{user_uri} already has {} client(s) in the database but no state in {}; \
                 refusing to mint a second identity (restore the state directory, or use \
                 another --state-dir that holds it)",
                clients.len(),
                dir.display()
            );
        }
        (mint_identity(&dir, &user_uri, domain)?, true)
    };
    let client = client_uri(domain, identity.signature_public_key());

    let account = match store
        .create_account(domain, &user_uri, clock.now_ms())
        .await
    {
        Ok(_) => "created",
        Err(JmapStoreError::AccountExists) => "already present",
        Err(error) => return Err(error).context("creating the JMAP account"),
    };

    let ours = |entries: Vec<KeyPackageEntry>| -> Vec<KeyPackageEntry> {
        entries
            .into_iter()
            .filter(|entry| entry.client_uri == client)
            .collect()
    };
    let existing = ours(key_packages.list_key_packages(&user).await?);
    let usable_one_time = existing
        .iter()
        .filter(|e| !e.last_resort && e.not_after >= required_until)
        .count();
    let mut stored_one_time = 0;
    for _ in usable_one_time..count {
        upload(
            key_packages,
            &user,
            &identity,
            KeyPackageKind::OneTime,
            required_until,
            clock,
        )
        .await?;
        stored_one_time += 1;
    }

    let last_resort = existing.iter().find(|e| e.last_resort);
    let last_resort_action = match last_resort {
        Some(entry) if entry.not_after >= required_until => "kept",
        Some(entry) => {
            // Only one last-resort KeyPackage per client (decision
            // mimid-1wgh.12.16): the one that runs out too soon goes.
            key_packages
                .delete_key_package(&user, &entry.reference)
                .await?;
            upload(
                key_packages,
                &user,
                &identity,
                KeyPackageKind::LastResort,
                required_until,
                clock,
            )
            .await?;
            "replaced"
        }
        None => {
            upload(
                key_packages,
                &user,
                &identity,
                KeyPackageKind::LastResort,
                required_until,
                clock,
            )
            .await?;
            "stored"
        }
    };

    let now_entries = ours(key_packages.list_key_packages(&user).await?);
    let now_seconds = clock.now_ms() / 1_000;
    let unexpired: Vec<&KeyPackageEntry> = now_entries
        .iter()
        .filter(|e| e.not_after >= now_seconds)
        .collect();
    let one_time = unexpired.iter().filter(|e| !e.last_resort).count();
    let earliest = unexpired.iter().map(|e| e.not_after).min().unwrap_or(0);
    let latest = unexpired.iter().map(|e| e.not_after).max().unwrap_or(0);
    println!("{user_uri}");
    println!(
        "  client       {client} ({})",
        if minted {
            "new identity"
        } else {
            "reloaded identity"
        }
    );
    println!("  jmap account {account}");
    println!(
        "  stored now   {stored_one_time} one-time, last-resort {last_resort_action}; \
         unclaimed: {one_time} one-time + 1 last-resort"
    );
    println!("  expiry       {} .. {} (UTC)", utc(earliest), utc(latest));
    Ok(())
}

/// Mints one KeyPackage of `kind`, checks it covers `required_until`, and
/// stores it through the validated upload path.
async fn upload(
    key_packages: &KeyPackages,
    user: &LocalUser,
    identity: &Identity,
    kind: KeyPackageKind,
    required_until: u64,
    clock: &dyn Clock,
) -> anyhow::Result<KeyPackageEntry> {
    let bytes = identity.key_package(kind).context("minting a KeyPackage")?;
    let now = UNIX_EPOCH + Duration::from_millis(clock.now_ms());
    let info = KeyPackage::tls_deserialize_exact(bytes.as_slice())
        .context("decoding the minted KeyPackage")?
        .verify(now)
        .context("verifying the minted KeyPackage")?;
    ensure!(
        info.not_after() >= required_until,
        "the minted KeyPackage expires {} UTC, before the end of --valid-through ({} UTC)",
        utc(info.not_after()),
        utc(required_until)
    );
    key_packages
        .upload_key_package(user, &bytes)
        .await
        .context("storing the KeyPackage")
}

/// Generates a fresh identity for `user_uri` with its private state in
/// `dir`, and records its public half in `identity.json`.
fn mint_identity(dir: &Path, user_uri: &str, domain: &Domain) -> anyhow::Result<Identity> {
    private_dir(dir)?;
    let mls = open_mls_store(dir)?;
    let identity =
        Identity::generate(user_uri.as_bytes(), mls).context("generating the identity")?;
    let record = IdentityFile {
        user_uri: user_uri.to_owned(),
        client_uri: client_uri(domain, identity.signature_public_key()),
        signature_public_key: hex(identity.signature_public_key()),
    };
    // Written to a temporary name and renamed, so a crash never leaves a
    // half-written record that would block a rerun.
    let temporary = dir.join("identity.json.tmp");
    let _ = std::fs::remove_file(&temporary);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .with_context(|| format!("creating {}", temporary.display()))?;
    serde_json::to_writer_pretty(&mut file, &record)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    std::fs::rename(&temporary, dir.join("identity.json"))?;
    Ok(identity)
}

/// Reloads the identity recorded in `dir`.
fn load_identity(dir: &Path, user_uri: &str, domain: &Domain) -> anyhow::Result<Identity> {
    private_dir(dir)?;
    let path = dir.join("identity.json");
    private_file(&path)?;
    let text = std::fs::read_to_string(&path)?;
    let record: IdentityFile =
        serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    ensure!(
        record.user_uri == user_uri,
        "{} is for {}, not {user_uri}",
        path.display(),
        record.user_uri
    );
    let public_key = unhex(&record.signature_public_key)
        .with_context(|| format!("{}: signature_public_key", path.display()))?;
    ensure!(
        record.client_uri == client_uri(domain, &public_key),
        "{}: client_uri does not match the signature key (another domain?)",
        path.display()
    );
    let mls = open_mls_store(dir)?;
    Identity::load(user_uri.as_bytes(), &public_key, mls)
        .with_context(|| format!("reloading the identity from {}", dir.display()))
}

/// Opens `<dir>/mls.sqlite`, creating it with mode 0600 first so SQLite
/// never creates it with the umask's mode.
fn open_mls_store(dir: &Path) -> anyhow::Result<mimi_mls::Store> {
    let path = dir.join("mls.sqlite");
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
    {
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error).with_context(|| format!("creating {}", path.display())),
    }
    private_file(&path)?;
    mimi_mls::Store::open(&path).with_context(|| format!("opening {}", path.display()))
}

/// Creates `dir` (and missing parents) with mode 0700, and refuses an
/// existing one its group or others can access.
fn private_dir(dir: &Path) -> anyhow::Result<()> {
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("creating {}", dir.display()))?;
    let mode = std::fs::metadata(dir)?.permissions().mode();
    ensure!(
        mode & FORBIDDEN_MODE_BITS == 0,
        "{} has mode {:#o}; it must not be accessible to group or others",
        dir.display(),
        mode & 0o777
    );
    Ok(())
}

/// Refuses a file its group or others can access.
fn private_file(path: &Path) -> anyhow::Result<()> {
    let mode = std::fs::metadata(path)
        .with_context(|| format!("inspecting {}", path.display()))?
        .permissions()
        .mode();
    ensure!(
        mode & FORBIDDEN_MODE_BITS == 0,
        "{} has mode {:#o}; it must not be accessible to group or others",
        path.display(),
        mode & 0o777
    );
    Ok(())
}

/// Checks, before [`Store::open`] touches it, that `database` exists, is
/// owned by this process's user, and has exactly the migrations this
/// build's mimid-server embeds, so the tool never migrates a database
/// under a mimid of another revision.
async fn check_database(database: &Path) -> anyhow::Result<()> {
    let metadata = std::fs::metadata(database).with_context(|| {
        format!(
            "{} does not exist; start mimid once with this config to create it",
            database.display()
        )
    })?;
    let euid = effective_uid()?;
    ensure!(
        metadata.uid() == euid,
        "{} is owned by uid {}, but this runs as uid {euid}; run mimid-seed as the user \
         that runs mimid, so the -wal and -shm files stay usable by mimid",
        database.display(),
        metadata.uid()
    );

    let mut connection = SqliteConnectOptions::new()
        .filename(database)
        .read_only(true)
        .busy_timeout(Duration::from_secs(5))
        .connect()
        .await
        .with_context(|| format!("opening {} read-only", database.display()))?;
    let applied: Vec<i64> =
        sqlx::query_scalar("SELECT version FROM _sqlx_migrations WHERE success = 1")
            .fetch_all(&mut connection)
            .await
            .with_context(|| {
                format!(
                    "{} has no migration table; is it a mimid database that mimid has opened?",
                    database.display()
                )
            })?;
    connection.close().await?;
    let applied: BTreeSet<i64> = applied.into_iter().collect();
    let embedded: BTreeSet<i64> = sqlx::migrate!("../../../crates/mimid-server/migrations")
        .iter()
        .map(|migration| migration.version)
        .collect();
    ensure!(
        applied == embedded,
        "{} has migrations {applied:?}, but this mimid-seed build has {embedded:?}; \
         build mimid-seed from the mimid revision that runs on this database",
        database.display()
    );
    Ok(())
}

/// This process's effective user ID, from `/proc/self/status` (Linux).
fn effective_uid() -> anyhow::Result<u32> {
    let status =
        std::fs::read_to_string("/proc/self/status").context("reading /proc/self/status")?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|ids| ids.split_whitespace().nth(1))
        .and_then(|euid| euid.parse().ok())
        .ok_or_else(|| anyhow!("no effective uid in /proc/self/status"))
}

/// The first second after the UTC day `date` (`YYYY-MM-DD`), in seconds
/// since the UNIX epoch.
fn end_of_day(date: &str) -> anyhow::Result<u64> {
    let bad = || anyhow!("--valid-through {date:?} is not YYYY-MM-DD");
    let mut parts = date.split('-');
    let (Some(y), Some(m), Some(d), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(bad());
    };
    let (y, m, d): (i64, i64, i64) = (
        y.parse().map_err(|_| bad())?,
        m.parse().map_err(|_| bad())?,
        d.parse().map_err(|_| bad())?,
    );
    ensure!(
        (1970..=9999).contains(&y) && (1..=12).contains(&m) && (1..=31).contains(&d),
        "--valid-through {date:?} is out of range"
    );
    let days = days_from_civil(y, m, d);
    ensure!(
        civil_from_days(days) == (y, m, d),
        "--valid-through {date:?} is not a date"
    );
    u64::try_from((days + 1) * 86_400).map_err(|_| bad())
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's
/// `days_from_civil`).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The inverse of [`days_from_civil`].
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// `seconds` since the UNIX epoch as `YYYY-MM-DD HH:MM:SS`, UTC.
fn utc(seconds: u64) -> String {
    let seconds = i64::try_from(seconds).unwrap_or(i64::MAX);
    let (y, m, d) = civil_from_days(seconds.div_euclid(86_400));
    let s = seconds.rem_euclid(86_400);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}",
        s / 3_600,
        s / 60 % 60,
        s % 60
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> anyhow::Result<Vec<u8>> {
    ensure!(text.len().is_multiple_of(2), "odd-length hex");
    (0..text.len())
        .step_by(2)
        .map(|i| {
            text.get(i..i + 2)
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .ok_or_else(|| anyhow!("not hex"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn end_of_day_is_the_next_midnight_utc() {
        // Oracle: `date -u -d 2026-11-18 +%s` (GNU coreutils).
        assert_eq!(end_of_day("2026-11-17").unwrap(), 1_794_960_000);
        assert_eq!(end_of_day("1970-01-01").unwrap(), 86_400);
        assert!(end_of_day("2026-02-30").is_err());
        assert!(end_of_day("2026-11").is_err());
    }

    #[test]
    fn utc_formats_epoch_seconds() {
        // Oracle: `date -u -d @1794959999 '+%F %T'`.
        assert_eq!(utc(1_794_959_999), "2026-11-17 23:59:59");
        assert_eq!(utc(0), "1970-01-01 00:00:00");
    }

    #[test]
    fn hex_round_trips() {
        let bytes = [0x00, 0x7f, 0xff, 0x10];
        assert_eq!(unhex(&hex(&bytes)).unwrap(), bytes);
        assert!(unhex("abc").is_err());
        assert!(unhex("zz").is_err());
    }
}
