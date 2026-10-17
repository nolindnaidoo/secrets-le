/**
 * The command line's help text and the flags it names.
 *
 * Word for word the Rust CLI's, because both install as `secrets-le` and a
 * person reading `--help` cannot tell which one they have.
 * `scripts/check-cli-parity.ts` compares the two outputs, and `cli.test.ts`
 * holds FLAGS equal to the flags this text names.
 */

export const USAGE = `usage: secrets-le [options] <file|dir>...
       secrets-le [options] --stdin
       secrets-le mcp
       secrets-le --version | --help

Finds hardcoded credentials and reports where they are — never what they
are. One JSON report per line on stdout when it is piped or redirected,
human summary on stderr.

Options:
  --sensitivity <level>   low, medium (default) or high. Higher reports
                          fewer, more certain findings.
  --no-api-keys           skip the API-key detectors
  --no-passwords          skip the password detectors
  --no-tokens             skip the token detectors
  --no-private-keys       skip the private-key detectors
  --strict                exit 2 if any file could not be read, rather
                          than reporting it and carrying on
  --stdin                 read one document from stdin
  --hidden                scan hidden files and directories too
  --no-ignore             scan files that .gitignore excludes

No preview is ever the whole value, and there is no flag that changes
that: a flag which turned it off would end up in someone's CI config.

Files that are not text, or that cannot be opened, are named on stderr
and carried in the report, and do not by themselves fail the run — every
repository has a PNG in it. --strict turns them back into a failure, and
a detector that gives up part way always does.

Exit codes: 0 nothing found · 1 findings · 2 malformed question.
For a run over many files, the exit code is the worst outcome in it.`;

export const FLAGS: readonly string[] = Object.freeze([
	'--strict',
	'--sensitivity',
	'--no-api-keys',
	'--no-passwords',
	'--no-tokens',
	'--no-private-keys',
	'--stdin',
	'--hidden',
	'--no-ignore',
]);
