# Unquarantine

Decrypt/restore artifacts from Windows Defender (and other) AV quarantine files.

This is a Windows-only .NET port inspired by `DeXRAY.pl`.

## Usage

```powershell
.\Unquarantine.exe "C:\path\to\DefenderQuarantine"
```

You can also pass a single file path; the tool will scan recursively and write outputs next to the inputs.

## Output files

Defender decryptions are written as:

- Primary decrypted output: `*.recovered`
- Sidecar: `*.recovered.name.txt` (best-effort filename-like hint derived from Defender metadata when available)

## Environment

- Build: requires `.NET SDK 8.0` (`dotnet` CLI)
- Run: the published binary is `self-contained` for `win-x64` (no extra .NET install needed)

## Notes

- Decrypted payloads may be detected by antivirus; if outputs are missing, test in a safe lab environment and consider temporary exclusions for your own working folder.

