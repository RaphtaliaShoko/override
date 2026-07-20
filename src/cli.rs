//! Command-line interface definition (clap derive).

use clap::{Parser, ValueEnum};
use std::path::PathBuf;

/// Processing order when multiple targets are given.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum Order {
    /// Run the whole pipeline on one file before moving to the next.
    Sequential,
    /// Run each phase across *all* files before starting the next phase.
    Batch,
}

/// `override` — securely destroy files so their content cannot be recovered.
///
/// The default destruction pipeline for every target is:
///
///   1. encrypt (crypto-shred: encrypt in place, then discard the key)
///   2. random overwrite  (phase A)
///   3. null overwrite
///   4. random overwrite  (phase B)
///   5. rename to random name(s)
///   6. delete (unlink)
///
/// Every write is flushed and fsync'd. The key is generated with a CSPRNG,
/// used once, and zeroized immediately -- it is never written or printed.
#[derive(Parser, Debug, Clone)]
#[command(
    name = "override",
    version,
    about = "Securely destroy files with crypto-shredding, multi-pass overwrites, and self-resilience.",
    long_about = None,
    after_help = "EXAMPLES:\n  \
        override secret.txt                 Run the default pipeline on one file\n  \
        override -v -r ./olddir             Recursively destroy a directory, verbosely\n  \
        override -e 2 -i 3 -n 1 a.bin b.bin Two encryption, three random, one null pass\n  \
        override -i 0 -e 0 -n 3 log.txt     Null-only wipe (no encryption/random)\n  \
        override -s /dev/urandom big.img    Use an explicit byte source for overwrites\n  \
        override --no-stop -u 5 target.dat  Loop forever, then 5 renames + delete on Ctrl-C\n  \
        override -o batch *.log             Batch order across many files\n  \
        override -p                         Type paths on stdin so they stay out of shell history\n\n\
        Note: on SSDs and copy-on-write filesystems (btrfs, ZFS, ...) logical\n\
        overwrites may not reach the original physical blocks; see the README."
)]
pub struct Cli {
    /// Files and/or directories to destroy.
    ///
    /// Passing paths here records them in your shell history, so the names of
    /// destroyed files remain visible afterwards. Use `--prompt` to type paths
    /// interactively instead (they are read from stdin and never appear as
    /// arguments).
    #[arg(value_name = "PATH", required_unless_present = "prompt")]
    pub paths: Vec<PathBuf>,

    /// Read one or more target paths interactively from stdin instead of (or in
    /// addition to) the command line, one per line, until a blank line or EOF.
    ///
    /// Because the paths are never passed as arguments, they are not saved in
    /// the shell's command history -- useful when the very existence of a file
    /// is sensitive. Any paths given on the command line are processed too.
    #[arg(short, long)]
    pub prompt: bool,

    /// Print detailed progress for every file, phase and pass.
    #[arg(short, long)]
    pub verbose: bool,

    /// Recurse into directories and process every file inside.
    #[arg(short, long)]
    pub recursive: bool,

    /// Number of encryption (crypto-shred) passes. 0 disables the phase.
    #[arg(short, long, value_name = "N", default_value_t = 1)]
    pub encryption: u32,

    /// Number of random-data overwrite passes (applied in BOTH random rounds).
    /// 0 disables random overwrite.
    #[arg(short, long, value_name = "N", default_value_t = 3)]
    pub iterations: u32,

    /// Number of zero-fill overwrite passes. 0 disables the null phase.
    #[arg(short, long, value_name = "N", default_value_t = 1)]
    pub null: u32,

    /// File used as the source of "random" bytes for overwrite passes,
    /// read in a streaming, wrap-around fashion. Defaults to the OS CSPRNG.
    ///
    /// WARNING: a predictable or low-entropy source file weakens the overwrite
    /// guarantee (the written bytes become guessable) and is NOT recommended for
    /// serious security use -- prefer the default CSPRNG. Crypto-shredding still
    /// applies regardless, but the random passes are only as unpredictable as
    /// this source.
    #[arg(short, long, value_name = "PATH")]
    pub source: Option<PathBuf>,

    /// Number of times to rename the file to a random name before deletion.
    #[arg(short = 'u', long, value_name = "N", default_value_t = 1)]
    pub rename: u32,

    /// Processing order when multiple targets are given.
    #[arg(short, long, value_enum, default_value_t = Order::Sequential)]
    pub order: Order,

    /// Loop encrypt->random->null->random indefinitely until interrupted,
    /// then rename+delete. A second interrupt forces immediate exit.
    #[arg(long)]
    pub no_stop: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        // Catches malformed clap attributes at test time.
        Cli::command().debug_assert();
    }

    #[test]
    fn defaults_match_documented_pipeline() {
        let cli = Cli::try_parse_from(["override", "file.txt"]).unwrap();
        assert_eq!(cli.encryption, 1);
        assert_eq!(cli.iterations, 3);
        assert_eq!(cli.null, 1);
        assert_eq!(cli.rename, 1);
        assert_eq!(cli.order, Order::Sequential);
        assert!(!cli.verbose && !cli.recursive && !cli.no_stop);
        assert_eq!(cli.paths, vec![PathBuf::from("file.txt")]);
    }

    #[test]
    fn zero_counts_disable_phases() {
        let cli = Cli::try_parse_from(["override", "-e", "0", "-i", "0", "-n", "0", "f"]).unwrap();
        assert_eq!((cli.encryption, cli.iterations, cli.null), (0, 0, 0));
    }

    #[test]
    fn requires_at_least_one_path() {
        assert!(Cli::try_parse_from(["override"]).is_err());
    }

    #[test]
    fn prompt_makes_positional_paths_optional() {
        // With --prompt, paths are read from stdin, so none are required.
        let cli = Cli::try_parse_from(["override", "--prompt"]).unwrap();
        assert!(cli.prompt);
        assert!(cli.paths.is_empty());
    }

    #[test]
    fn prompt_still_accepts_command_line_paths() {
        let cli = Cli::try_parse_from(["override", "-p", "a.txt"]).unwrap();
        assert!(cli.prompt);
        assert_eq!(cli.paths, vec![PathBuf::from("a.txt")]);
    }
}
