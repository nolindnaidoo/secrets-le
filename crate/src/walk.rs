//! Turning what the caller named into the list of files to scan.
//!
//! Directories are walked with ripgrep's `ignore`, so "what this tool
//! scans" and "what ripgrep scans" are the same answer. A file named
//! explicitly is always scanned, ignore rules included: you asked for it.
//!
//! Unlike paths-le's walker there is no format filter. A credential can
//! be hardcoded in any text file, and a scanner that only looked at the
//! extensions it recognised would report a clean tree while sitting next
//! to a `.bak` full of passwords.

use std::path::{Path as StdPath, PathBuf};

#[derive(Debug, Clone)]
pub(crate) struct WalkOptions {
    pub(crate) hidden: bool,
    pub(crate) respect_ignore: bool,
}

impl Default for WalkOptions {
    fn default() -> Self {
        Self {
            hidden: false,
            respect_ignore: true,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Walked {
    pub(crate) files: Vec<PathBuf>,
    /// How many entries `.gitignore` or the hidden rule kept out.
    ///
    /// Counted rather than inferred, because "we scanned everything" and
    /// "we scanned what git tracks" are different claims and the second
    /// one has to be visible. A secret in an ignored file is still a
    /// secret on the disk.
    pub(crate) skipped: usize,
    /// The skipped files whose *names* say they probably hold a
    /// credential.
    ///
    /// The bare count is nearly useless on a real repository: it comes
    /// out around 28,000, almost all of it `node_modules`, and a number
    /// that large is one people learn to scroll past. Measured on seven
    /// repositories before this list existed.
    ///
    /// These are the ones where "skipped" is actually dangerous, and
    /// there are few enough to name.
    pub(crate) skipped_of_note: Vec<PathBuf>,
}

/// File names that ordinarily hold credentials.
///
/// Deliberately short and literal rather than clever. Every entry earns
/// its place by being a file whose whole purpose is to hold secrets, and
/// which is also routinely gitignored — that intersection is the reason
/// the list exists.
/// Directories whose contents belong to someone else.
///
/// Without this the noteworthy list fills with `.npmrc` files from
/// inside a downloaded VS Code bundle — six per repository, none of them
/// the user's, which is the `node_modules` problem one level down. A
/// warning that is always there is a warning nobody reads.
const VENDORED: [&str; 8] = [
    "node_modules",
    ".vscode-test",
    "vendor",
    "target",
    "dist",
    "build",
    ".venv",
    "site-packages",
];

fn is_vendored(path: &StdPath) -> bool {
    path.components().any(|component| {
        component
            .as_os_str()
            .to_str()
            .is_some_and(|name| VENDORED.contains(&name))
    })
}

/// File names that ordinarily hold credentials, lowercased before the
/// comparison — a `.PEM` on a case-insensitive filesystem is the same
/// file as a `.pem`.
const CREDENTIAL_NAMES: [&str; 6] = [
    ".npmrc",
    ".netrc",
    ".pgpass",
    "credentials",
    "id_rsa",
    "id_ed25519",
];
const CREDENTIAL_SUFFIXES: [&str; 4] = [".pem", ".key", ".p12", ".pfx"];

fn is_of_note(path: &StdPath) -> bool {
    if is_vendored(path) {
        return false;
    }
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let name = name.to_lowercase();
    name == ".env"
        || name.starts_with(".env.")
        || CREDENTIAL_SUFFIXES
            .iter()
            .any(|suffix| name.ends_with(suffix))
        || CREDENTIAL_NAMES.contains(&name.as_str())
}

/// Collect every file to scan, in a stable order.
///
/// The sort is not cosmetic: `ignore` makes no ordering guarantee, and a
/// report whose lines move between two runs over an unchanged tree
/// cannot be diffed — which is most of what a report in CI is for.
pub(crate) fn collect(inputs: &[PathBuf], options: &WalkOptions) -> Result<Walked, String> {
    let mut files = Vec::new();
    let mut skipped = 0;
    let mut skipped_of_note = Vec::new();

    for input in inputs {
        let metadata =
            std::fs::metadata(input).map_err(|error| format!("{}: {error}", input.display()))?;

        if metadata.is_file() {
            files.push(input.clone());
            continue;
        }

        let walked = walk_directory(input, options)?;
        files.extend(walked.files);
        skipped += walked.skipped;
        skipped_of_note.extend(walked.skipped_of_note);
    }

    files.sort();
    files.dedup();
    skipped_of_note.sort();
    skipped_of_note.dedup();
    Ok(Walked {
        files,
        skipped,
        skipped_of_note,
    })
}

fn walk_directory(root: &StdPath, options: &WalkOptions) -> Result<Walked, String> {
    let mut permissive = ignore::WalkBuilder::new(root);
    permissive
        .hidden(false)
        .git_ignore(false)
        .git_global(false)
        .git_exclude(false)
        .ignore(false)
        .parents(false)
        .follow_links(false);

    let mut builder = ignore::WalkBuilder::new(root);
    builder
        .hidden(!options.hidden)
        .git_ignore(options.respect_ignore)
        .git_global(options.respect_ignore)
        .git_exclude(options.respect_ignore)
        .ignore(options.respect_ignore)
        .parents(options.respect_ignore)
        // Never followed. A link out of the tree would have this scan
        // reading files the caller did not point it at, and reporting
        // their paths.
        .follow_links(false);

    let files = files_under(&mut builder, root)?;
    // Counted by difference rather than by instrumenting the walk: the
    // question is how many files a caller might expect to have been
    // looked at and were not.
    let everything = if options.respect_ignore || !options.hidden {
        files_under(&mut permissive, root)?
    } else {
        files.clone()
    };

    let scanned: std::collections::HashSet<&PathBuf> = files.iter().collect();
    let skipped_of_note = everything
        .iter()
        .filter(|path| !scanned.contains(path) && is_of_note(path))
        .cloned()
        .collect();

    Ok(Walked {
        skipped: everything.len().saturating_sub(files.len()),
        skipped_of_note,
        files,
    })
}

fn files_under(builder: &mut ignore::WalkBuilder, root: &StdPath) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    for entry in builder.build() {
        let entry = entry.map_err(|error| format!("{}: {error}", root.display()))?;
        if entry.file_type().is_some_and(|kind| kind.is_file()) {
            files.push(entry.path().to_path_buf());
        }
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::TempTree;

    fn names(walked: &Walked) -> Vec<String> {
        walked
            .files
            .iter()
            .map(|path| {
                path.file_name()
                    .expect("a name")
                    .to_string_lossy()
                    .into_owned()
            })
            .collect()
    }

    /// Every text file, whatever its extension — a credential does not
    /// care what the file is called.
    #[test]
    fn a_directory_yields_every_file_regardless_of_extension() {
        let tree = TempTree::new("walk-all");
        tree.write("a.json", "{}");
        tree.write("notes.md", "x");
        tree.write("config.bak", "x");
        tree.write("Makefile", "x");
        let walked = collect(&[tree.path().to_path_buf()], &WalkOptions::default()).expect("walks");
        assert_eq!(
            names(&walked),
            ["Makefile", "a.json", "config.bak", "notes.md"]
        );
    }

    #[test]
    fn the_order_is_stable() {
        let tree = TempTree::new("walk-order");
        for name in ["z.env", "a.env", "m.env"] {
            tree.write(name, "x");
        }
        let first = collect(&[tree.path().to_path_buf()], &WalkOptions::default()).expect("walks");
        let second = collect(&[tree.path().to_path_buf()], &WalkOptions::default()).expect("walks");
        assert_eq!(names(&first), ["a.env", "m.env", "z.env"]);
        assert_eq!(first, second);
    }

    /// A secret in an ignored file is not going to be committed, which
    /// is the threat — but it is still a secret on the disk, so the
    /// count of what was held back has to be visible.
    #[test]
    fn ignored_files_are_skipped_and_counted() {
        let tree = TempTree::new("walk-ignore");
        tree.mkdir(".git");
        tree.write(".gitignore", "secret.env\n");
        tree.write("secret.env", "PASSWORD=hunter2hunter2");
        tree.write("kept.env", "x");

        let walked = collect(&[tree.path().to_path_buf()], &WalkOptions::default()).expect("walks");
        assert!(names(&walked).contains(&"kept.env".to_string()));
        assert!(!names(&walked).contains(&"secret.env".to_string()));
        assert!(walked.skipped > 0, "the skip must be countable, not silent");
    }

    #[test]
    fn nothing_is_skipped_when_nothing_is_excluded() {
        let tree = TempTree::new("walk-noskip");
        tree.write("a.env", "x");
        let walked = collect(
            &[tree.path().to_path_buf()],
            &WalkOptions {
                hidden: true,
                respect_ignore: false,
            },
        )
        .expect("walks");
        assert_eq!(walked.skipped, 0);
    }

    #[test]
    fn hidden_files_are_scanned_on_request() {
        let tree = TempTree::new("walk-hidden");
        tree.write(".env", "PASSWORD=hunter2hunter2");
        let default =
            collect(&[tree.path().to_path_buf()], &WalkOptions::default()).expect("walks");
        assert!(default.files.is_empty());
        assert_eq!(default.skipped, 1);

        let all = collect(
            &[tree.path().to_path_buf()],
            &WalkOptions {
                hidden: true,
                ..WalkOptions::default()
            },
        )
        .expect("walks");
        assert_eq!(names(&all), [".env"]);
    }

    /// A `.env` is the single most likely place for a credential and is
    /// hidden *and* usually gitignored. Pinned so the default can never
    /// quietly become "scans nothing that matters".
    #[test]
    fn the_default_walk_misses_dotenv_and_says_so() {
        let tree = TempTree::new("walk-dotenv");
        tree.mkdir(".git");
        tree.write(".gitignore", ".env\n");
        tree.write(".env", "PASSWORD=hunter2hunter2");
        let walked = collect(&[tree.path().to_path_buf()], &WalkOptions::default()).expect("walks");
        assert!(walked.files.is_empty());
        assert!(walked.skipped >= 1, "the miss must be reported as a count");
    }

    #[test]
    fn an_explicitly_named_file_beats_the_ignore_rules() {
        let tree = TempTree::new("walk-explicit");
        tree.mkdir(".git");
        tree.write(".gitignore", ".env\n");
        let file = tree.write(".env", "PASSWORD=hunter2hunter2");
        let walked = collect(&[file], &WalkOptions::default()).expect("walks");
        assert_eq!(names(&walked), [".env"]);
    }

    /// The names that make "skipped" dangerous, called out individually
    /// because the bare count is ~28,000 on a real repository and
    /// nobody reads a number that size.
    #[test]
    fn a_skipped_credential_file_is_named_not_just_counted() {
        let tree = TempTree::new("walk-ofnote");
        tree.mkdir(".git");
        tree.write(".gitignore", ".env\nsecrets.pem\nboring.log\n");
        tree.write(".env", "PASSWORD=hunter2hunter2");
        tree.write("secrets.pem", "-----BEGIN PRIVATE KEY-----");
        tree.write("boring.log", "nothing");
        let walked = collect(&[tree.path().to_path_buf()], &WalkOptions::default()).expect("walks");

        let noted: Vec<String> = walked
            .skipped_of_note
            .iter()
            .map(|p| {
                p.file_name()
                    .expect("a name")
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        assert!(noted.contains(&".env".to_string()), "{noted:?}");
        assert!(noted.contains(&"secrets.pem".to_string()), "{noted:?}");
        assert!(!noted.contains(&"boring.log".to_string()), "{noted:?}");
        assert!(walked.skipped >= noted.len());
    }

    /// A `.npmrc` inside a downloaded editor bundle is not the user's,
    /// and six of them per repository is how the useful warning became
    /// noise. Found by running the binary over the fleet.
    #[test]
    fn a_credential_name_inside_a_vendored_tree_is_not_of_note() {
        let tree = TempTree::new("walk-vendored");
        tree.mkdir(".git");
        tree.write(".gitignore", "node_modules/\n.vscode-test/\n");
        tree.write("node_modules/pkg/.npmrc", "x");
        tree.write(".vscode-test/app/.npmrc", "x");
        let walked = collect(&[tree.path().to_path_buf()], &WalkOptions::default()).expect("walks");
        assert!(
            walked.skipped_of_note.is_empty(),
            "{:?}",
            walked.skipped_of_note
        );
        assert!(walked.skipped >= 2, "they are still counted");
    }

    #[test]
    fn a_missing_input_is_refused_by_name() {
        let tree = TempTree::new("walk-missing");
        let error =
            collect(&[tree.path().join("nope")], &WalkOptions::default()).expect_err("a refusal");
        assert!(error.contains("nope"), "{error}");
    }

    #[test]
    fn naming_the_same_file_twice_scans_it_once() {
        let tree = TempTree::new("walk-dedupe");
        let file = tree.write("a.env", "x");
        let walked = collect(&[file.clone(), file], &WalkOptions::default()).expect("walks");
        assert_eq!(walked.files.len(), 1);
    }
}
