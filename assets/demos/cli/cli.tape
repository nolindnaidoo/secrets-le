# secrets-le, the command line, driving the release build against input/.
#   cargo build --release in crate/, then from letools-site:
#   bun run record:demo ../secrets-le cli
# Runs in a temp copy, so nothing here is changed and no home path is shown.

Set Shell "bash"
Set FontSize 28
Set Width 1600
Set Height 1000
Set Padding 32
Set TypingSpeed 45ms
Set Theme "Catppuccin Mocha"

Hide
Type `D=$PWD; cd "$(mktemp -d /tmp/secrets-le.XXXX)" && cp -R "$D/input/." . && export PATH="$D/../../../crate/target/release:$PATH" && PS1="$ " && clear`
Enter
Type "cut -d= -f1 app.env"
Enter
Sleep 2.5s
Show

Type "secrets-le app.env > findings.jsonl"
Enter
Sleep 5s

Type "head -c 96 findings.jsonl"
Enter
Sleep 3s
