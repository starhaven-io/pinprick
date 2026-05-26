---
title: completions
description: Generate shell completions for pinprick.
---

Generate shell completions for `pinprick`. Output is written to stdout — redirect it to the location your shell loads completions from.

```bash
pinprick completions <SHELL>
```

`<SHELL>` is one of: `bash`, `elvish`, `fish`, `powershell`, `zsh`.

## Install

### zsh

```bash
pinprick completions zsh > ~/.zfunc/_pinprick
```

Make sure `~/.zfunc` is on your `fpath` and `autoload -Uz compinit && compinit` runs in your `.zshrc`.

### bash

```bash
pinprick completions bash | sudo tee /etc/bash_completion.d/pinprick > /dev/null
```

Or, without root:

```bash
mkdir -p ~/.local/share/bash-completion/completions
pinprick completions bash > ~/.local/share/bash-completion/completions/pinprick
```

### fish

```bash
pinprick completions fish > ~/.config/fish/completions/pinprick.fish
```

### PowerShell

```powershell
pinprick completions powershell | Out-String | Invoke-Expression
```

For persistent completions, append the output to your PowerShell profile (`$PROFILE`).

## Updating

Regenerate completions after every pinprick upgrade — new subcommands and flags are only discoverable through the regenerated file.
