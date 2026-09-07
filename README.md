# Remote Elastic Agent Install/Uninstall Toolkit

PowerShell scripts to validate WinRM/Fleet connectivity and then remotely
install, enroll, and (if needed) uninstall Elastic Agent on Windows hosts —
without touching Group Policy, SCCM, or any third-party deployment tool.

Everything runs from a single Windows controller machine over WinRM.

## Files in this folder

| File | Purpose |
|---|---|
| `Invoke-EndToEndAgentDeployment.ps1` | **Start here.** Runs the full flow: connectivity check → install/enroll → summary, in one command. |
| `multi-windows-winrm-check.ps1` / `.sh` | Validates WinRM access and Fleet Server reachability for a list of targets, without installing anything. |
| `Install-ElasticAgentsRemote.ps1` | Copies the Elastic Agent ZIP to each target, installs it as a service, and enrolls it in Fleet. |
| `Uninstall-ElasticAgentsRemote.ps1` | Removes Elastic Agent from a list of targets (for rollback/retry). |
| `Initialize-WinRMCredential.ps1` | One-time helper: saves a DPAPI-protected WinRM admin credential file. |
| `Initialize-KibanaApiKey.ps1` | One-time helper: saves a DPAPI-protected Kibana API key file (only needed if you want Fleet to auto-fetch enrollment tokens). |
| `windows-targets.txt` | Plain list of target IPs/hostnames, one per line (`#` for comments). |
| `elastic-agent-<version>-windows-x86_64.zip` | The Elastic Agent Windows package to deploy. Download the version you need from the [Elastic Agent downloads page](https://www.elastic.co/downloads/elastic-agent). |

Generated at runtime (not committed, safe to delete/regenerate): `winrm-credential.xml`,
`fleet-enrollment-token.xml`, `kibana-api-key.xml`, and timestamped `*.log` files.

## Prerequisites

1. **Controller machine**: Windows, PowerShell 5.1+, run as Administrator.
2. **Network access** from the controller to each target's TCP `5985` (WinRM) and
   from each target to the Fleet Server's TCP port (default `8220`).
3. **An administrator account** on the target Windows machines (domain or local).
4. **A Fleet enrollment token** for the agent policy you want the hosts to join
   (Kibana → **Fleet → Agent policies → your policy → Enrollment tokens**).
5. **The Elastic Agent Windows ZIP** placed in this folder, matching the version
   you intend to install.
6. Scripts must not be blocked by Windows ("Mark of the Web"). If you copy these
   files from a browser download, a zip, or a network share, unblock them once:
   ```powershell
   Get-ChildItem *.ps1 | Unblock-File
   ```
   You'll know this is needed if you see: *"...is not digitally signed. You
   cannot run this script on the current system."*

## One-time setup

```powershell
# 1. List your Windows targets, one IP/hostname per line
notepad .\windows-targets.txt

# 2. Save a WinRM admin credential (prompts once, encrypted for your Windows user)
.\Initialize-WinRMCredential.ps1 -CredentialFile .\winrm-credential.xml

# 3. Get a Fleet enrollment token from Kibana (Fleet -> Agent policies -> your
#    policy -> Enrollment tokens -> copy). Save it as plain text, e.g.:
notepad .\fleet-enrollment-token.txt
```

You do **not** need to manually convert the token to XML — the end-to-end
script does that automatically (see below).

## Running the full deployment

```powershell
.\Invoke-EndToEndAgentDeployment.ps1 `
    -FleetServer 10.50.128.61 -FleetPort 8220 `
    -TargetsFile .\windows-targets.txt `
    -CredentialFile .\winrm-credential.xml `
    -EnrollmentTokenTextFile .\fleet-enrollment-token.txt `
    -AgentZip .\elastic-agent-8.18.8-windows-x86_64.zip `
    -Insecure
```

- Drop `-Insecure` once your Fleet Server uses a certificate trusted by the
  target machines (or pass `-FleetCaCertificate .\fleet-ca.crt` instead).
- Use `-Targets 10.50.130.29,10.50.130.30` instead of `-TargetsFile` for an
  ad-hoc list.
- Add `-SkipConnectivityCheck` to jump straight to install if you already
  validated connectivity separately.
- Logs for each stage are written next to this folder as
  `e2e-<timestamp>-01-connectivity.log` and `e2e-<timestamp>-02-install.log`.

### Alternative: fetch the enrollment token live from Fleet's API

Instead of a saved token file, you can have the script pull a valid,
currently-active enrollment token straight from Kibana at runtime:

```powershell
.\Initialize-KibanaApiKey.ps1 -ApiKeyFile .\kibana-api-key.xml

.\Invoke-EndToEndAgentDeployment.ps1 `
    -FleetServer 10.50.128.61 -TargetsFile .\windows-targets.txt `
    -CredentialFile .\winrm-credential.xml `
    -KibanaUrl https://my-kibana-host:5601 `
    -KibanaApiKeyFile .\kibana-api-key.xml `
    -PolicyId <your-agent-policy-id> `
    -AgentZip .\elastic-agent-8.18.8-windows-x86_64.zip `
    -Insecure
```

The Kibana API key needs Fleet/Integrations read privileges. Find the
`PolicyId` under **Fleet → Agent policies → your policy → Settings**.

## Running the stages individually

```powershell
# Connectivity only, no install
.\multi-windows-winrm-check.ps1 -FleetServer 10.50.128.61 -FleetPort 8220 `
    -TargetsFile .\windows-targets.txt -CredentialFile .\winrm-credential.xml

# Install only (skips a connectivity check)
.\Install-ElasticAgentsRemote.ps1 -FleetServer 10.50.128.61 `
    -TargetsFile .\windows-targets.txt -CredentialFile .\winrm-credential.xml `
    -EnrollmentTokenFile .\fleet-enrollment-token.xml `
    -AgentZip .\elastic-agent-8.18.8-windows-x86_64.zip -Insecure

# Remove Elastic Agent from targets
.\Uninstall-ElasticAgentsRemote.ps1 -TargetsFile .\windows-targets.txt `
    -CredentialFile .\winrm-credential.xml
```

## Behavior you should know about

- **Idempotent by default**: if a target already has Elastic Agent installed,
  the install step reports `ALREADY_INSTALLED` and skips it. No `--force` is
  ever used. Run `Uninstall-ElasticAgentsRemote.ps1` first if you need a clean
  reinstall.
- **Upload caching**: the ZIP is staged remotely under a path keyed by its own
  SHA-256 hash (`C:\ProgramData\Elastic\Staging\elastic-agent-<hash>`). Re-runs
  reuse a matching, already-verified copy instead of re-uploading 200+ MB.
- **Failed runs keep their staging folder** on the target (for troubleshooting
  and so the next run can reuse the uploaded ZIP). Safe to delete manually.
- **`--unprivileged`**: pass `-Unprivileged` to install the agent as a
  reduced-privilege service account instead of SYSTEM.
- **Stale lock detection**: if a previous run crashed mid-install, the next run
  detects a leftover `elastic-agent.lock` and fails with a clear message
  instead of a confusing install error.

## Troubleshooting

| Symptom | Cause / Fix |
|---|---|
| `...is not digitally signed. You cannot run this script...` | The file has Windows' Mark-of-the-Web flag. Run `Get-ChildItem *.ps1 \| Unblock-File` in this folder. |
| `Expand-Archive`/`Microsoft.PowerShell.Archive` module error | Fixed already — extraction uses `[IO.Compression.ZipFile]` directly and no longer depends on that module. |
| Install fails with a JSON log line (e.g. `"SSL/TLS verifications disabled"`) as the error | This is a normal WARN log from `elastic-agent.exe`, not a real failure. Already handled — the scripts no longer treat stderr output as fatal. |
| `could not get version. failed to communicate with running daemon...` | Happens when `elastic-agent version` tries to reach a not-yet-running daemon. Already fixed with `--binary-only` + relaxed error handling. |
| Script reports `FAILED` but the agent actually shows up in Fleet | Check the install log; a prior bug (now fixed) could report a false failure due to a benign stderr log line even though the install succeeded. Re-run — it will correctly detect `ALREADY_INSTALLED`. |
| Want to fully reset a target | Run `Uninstall-ElasticAgentsRemote.ps1` against it, confirm it's gone from Fleet's **Agents** tab, then re-run the deployment. |

## Security notes

- `winrm-credential.xml`, `fleet-enrollment-token.xml`, and `kibana-api-key.xml`
  are DPAPI-encrypted and only usable by the same Windows user account on the
  same machine that created them. Do not copy them elsewhere.
- Enrollment tokens and API keys are redacted from logs and never printed to
  the console.
- Prefer removing `-Insecure` and supplying `-FleetCaCertificate` once your
  Fleet Server has a proper certificate, especially outside of test/lab use.
