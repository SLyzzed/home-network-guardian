# Final privacy and security audit

Audit date: 2026-11-13. Branch: `simplify-windows-launcher`.
No commits, pushes, history edits, downloads or live network scans were performed.

## A. Issues found

- An ignored `report.html` contains actual network addresses. It is private user
  data and was deliberately preserved. It must not enter a public source archive.
  Its containing workspace is in OneDrive, so it may already have synced.
- Obsolete Python environment files contained absolute local account paths.
  Python caches, test outputs and synthetic HTML were unnecessary distribution
  artifacts.
- Unexpected startup and saved-report helper exceptions could display account
  paths or other identity-bearing OS messages.
- Saving under LOCALAPPDATA did not reject network drive redirection, OneDrive,
  junctions, symbolic links or alternate data streams.
- .NET IPv4 parsing accepted alternate numeric spellings. This created different
  interpretations between validation and downstream scanner arguments.
- XML external resolution was already disabled, but document size was unbounded
  at the parser.
- Two historical commits contain a personal email in author and committer
  metadata. No credential was found; an email is not an authentication secret.

## B. Remediation and confirmed protections

- Unexpected exceptions now receive generic guidance. Known prerequisite and
  network-selection messages remain actionable. Scanner stderr and XML parse
  errors are never exported to the report.
- Report paths must be absolute on a fixed local drive. Known OneDrive roots,
  alternate streams and reparse points in existing path components are rejected.
  Checks occur before and after creating the application directory. Failure does
  not select Desktop, the working directory or another fallback location.
- Network and target addresses must use canonical dotted decimal syntax.
  Only RFC 1918 ranges are eligible, limited to at most 256 addresses. Public,
  documentation, loopback, link-local, carrier-grade NAT, IPv6 and hostname
  targets remain rejected. Private literals in tests exercise these restrictions;
  they are synthetic inputs, not captured network configuration.
- XML parsing has a 16 MiB character limit, no external resolver and no entity
  expansion from DTDs. Normal Nmap DOCTYPE declarations remain compatible.
- Reports use numbered devices, a fixed manufacturer vocabulary and fixed service
  labels. IPs, full MACs, hostnames, serials, product/version banners, HTTP headers,
  certificate subjects/issuers/SANs and script output are omitted. Certificate and
  RTSP presence statements retain useful evidence without copying identities.
- No telemetry, automatic AI requests or uploads were found. Nmap is the sole
  network probing component. `-n` prevents reverse DNS lookups. Only the existing
  eight TCP ports and `ssl-cert,rtsp-methods` scripts are requested. Consent precedes
  discovery; adapter/address/scope are rechecked afterward. Processes have bounded
  deadlines and termination handling. Executables and validated arguments are
  separate, with shell execution disabled.
- Raw XML and stderr stay in process memory; no temporary scan files are written.
  Only the filtered review is saved. No automatic clipboard action occurs; button
  callbacks contain copy/open errors and retain their dependencies after scope exit.
- AI_Prompt.txt already instructs the assistant to treat findings as untrusted
  data, avoid contacting devices or researching private identifiers, and acknowledge
  uncertainty. No prompt change was necessary. The report and README explain manual
  AI sharing, clipboard retention and inference from device counts/service mixtures.
- Ignore rules now also cover release archives, logs, temporary/backup files,
  environment files and common private-key files. Ignore rules are not a secret
  scanner and do not prevent force-adding files.

## C. Files modified, relocated, added or removed

Changed during this audit: Guardian.ps1, .gitignore, README.md,
tests/Guardian.Tests.ps1, tests/Run-Tests.ps1 and the regenerated synthetic
samples/AI_Review.example.txt. Public rejection examples now use documentation
addresses; synthetic MAC and identity examples are explicitly fictional.

Moved the optional saved-report developer helper from the repository root to
tools/Show-SavedReport.ps1, fixed its relative import and masked its exceptions.
Added tests/Privacy.Tests.ps1, tools/Build-Release.ps1 and this report.

Removed obsolete .venv, .pytest_cache, .test-temp-phase2a, .test-temp-phase2b,
tests/__pycache__, synthetic-example-report.html and samples/service_example.html.
The real report.html was not removed or modified.

The working tree already contained the Python implementation, Python tests,
pyproject.toml and uv.lock deletions when this audit began; those changes were
preserved. Existing PowerShell application files, tests and synthetic fixtures
were also already untracked. No application functionality was removed by this
audit. LICENSE and useful synthetic XML fixtures remain.

The generated ignored dist/HomeNetworkGuardian.zip was opened and its entries
verified against exactly: Start Guardian.bat, Guardian.ps1, AI_Prompt.txt,
README.md and LICENSE. Tests, tools, audit notes, private reports and Git metadata
are excluded. Always rebuild with the allowlist script after changing release files.

## D. Git history findings

All three commits reachable from every local branch and remote-tracking ref were
reviewed, including committed file contents and author/committer metadata:
`e186fae`, `522765d`, `9cacde0`. Local main, simplify-windows-launcher and origin/main
resolve to the last commit; origin/HEAD points to origin/main. The index had no
staged changes. No remote refs were fetched, so this finding covers locally known
history, not independently verified current remote state, forks or deleted refs.

No real scan results, credentials, tokens, private keys, personal Windows paths,
SSIDs or identity-bearing device data were found in historical file contents.
Documentation addresses, deliberately fabricated MACs, private-range validation
tests and application network constants are legitimate code/test data.

Commits `522765d` and `9cacde0` expose a personal email in author and committer
metadata; this is not associated with a particular file. The initial commit uses
a GitHub noreply address. The LICENSE credit and repository handle are intentional
project attribution and were preserved. The actual email is not reproduced here.

If email removal is required, changing the working tree is insufficient. Obtain
explicit approval for metadata history rewriting, coordinate with collaborators,
and address remote copies/forks/caches where possible. Configure an appropriate
noreply identity for future commits. No history was rewritten and no branches
were deleted. No exposed credential requiring rotation was identified.

## E. Remaining risks and manual actions

- Decide whether the historical author email is acceptable before publishing Git
  history. The ZIP contains no Git metadata.
- Keep the preserved private report out of public uploads. Decide privately whether
  to relocate it and review OneDrive retention/sharing. This audit cannot undo any
  earlier sync or third-party disclosure.
- Report counts and service combinations still reveal household characteristics.
  Users must review manually shared text, especially after editing prompts/reports.
  Clipboard history, other sync/backup tools, device administration and an AI
  provider's retention are outside Guardian's control.
- The report inherits local folder permissions and is not encrypted. Same-user
  malware or administrators can access it. Path checks are best-effort against
  redirection, not a security boundary against a concurrent local attacker.
- Nmap/Npcap and their script databases must come from a trusted installation.
  XML input is capped at parsing, but redirected process output is captured in
  memory before that cap; a compromised scanner could exhaust memory. Windows,
  antivirus or crash diagnostics may independently retain process information.
- RFC 1918 addressing does not establish ownership or prove a home environment;
  explicit user permission remains essential. Network routing can change after
  consent. Existing manual Windows testing remains useful; this audit intentionally
  performed no live scan and adds no claim of device or network safety.

## F. Automated results

Windows PowerShell 5.1 / Pester suite: **74 passed, 0 failed, 0 skipped**.
Includes IPv4/IPv6/MAC/hostname/serial/header/certificate/banner suppression, safe
clue retention, XML entity/size checks, path redirection rejection, generic errors,
scope and command restrictions, cancellation, consent revalidation, deadlines,
mocked scanner lifecycle, saving/fallback behavior and no web-upload calls.
Popup regressions exercise buttons with synthetic data and restore the previous
clipboard; external scanner and Notepad actions are mocked. No live probes ran.

Release allowlist archive verification passed. Synthetic example regeneration
passed. `git diff --check` and `git diff --cached --check` passed.

## G. Release decision

The verified ZIP is ready for distribution under the stated limitations. Publishing
the repository with its existing Git history requires an explicit decision about
the personal email metadata. Do not publish a ZIP of the entire working folder.
No commits or pushes were made.
