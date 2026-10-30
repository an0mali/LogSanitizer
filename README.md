Hi! Welcome to my log sanitizer project.

# Local diagnostic sanitizer

`Sanitize-File.ps1` runs offline with PowerShell 7.2+ and built-in .NET libraries. It writes a **candidate requiring human review**, not a certification that a file is safe to disclose. No network calls, telemetry, external services, or saved reverse mapping are used.

```powershell
./Sanitize-File.ps1 -InputPath ./client.log, ./notes.txt -OutputDirectory ./review -SensitiveLiteral 'Jane Smith','CONTOSO','PC-123'
./Sanitize-File.ps1 -InputPath ./report.docx -OutputDirectory ./review -SensitiveValuesFile ./local-sensitive-values.txt
pwsh -NoProfile -File ./tests/Smoke.ps1
```

The sensitive-values file contains one literal per line. Keep it local. All inputs in one invocation share case-insensitive identifier mappings; mappings reset between invocations. Originals are never modified and existing output files are never overwritten. Outputs use UTF-8; protect the output directory like the originals until review is complete. Source filenames are retained and may themselves need anonymization before upload.

## Format support

| Input | Behavior |
| --- | --- |
| TXT, textual logs, SCCM/CMTrace logs | Preserve text layout and CMTrace markers; replace detected values. UTF-8 and BOM-marked UTF-16 supported. |
| CSV | Text replacement, retaining delimiters in typical rows. Review CSV structure after redaction. |
| EVTX | Windows only: `Get-WinEvent` reads records and exports raw event XML into a text file. Provider message rendering, original EVTX binary format, and opaque event payload decoding are not supported. Not every event channel/provider has been validated. |
| DOCX | Extract paragraph text from the main document, headers, footers, comments, footnotes and endnotes. Formatting, embedded objects, images, and metadata are excluded. |
| XLSX | Export worksheet cell addresses and cached values as tab-separated text. Shared/inline strings supported. Formulas, formatting, images, embedded files, workbook metadata, sheet names, and uncached formula results are excluded. No formula execution. |
| EML | Plain UTF-8/UTF-16 email only. Multipart, HTML, encoded bodies and attachments are rejected; export them locally to text first. |
| DOC, XLS, XLSB, MSG, PST, OST, RTF, PDF, EVT, ETL, macro-enabled Office | Rejected. Export locally using a trusted application before processing. |

This implementation does **not** meet universal Office/email/Event Viewer compatibility. It deliberately emits text exports rather than copying potentially hidden binary content into an upload artifact. Unknown binary input and invalid UTF-8 fail rather than silently corrupting data. Large files are processed in memory; use suitably sized exports. A batch can leave completed review outputs if a later input fails.

## Detection and limits

Built-in patterns cover common credential assignments, private keys, bearer/basic tokens, some cloud tokens, email addresses, IPv4/IPv6, MACs, SIDs, profile paths, labeled identities, common host suffixes, URLs, US SSNs and phone-like numbers. Full URLs are replaced because query strings frequently contain secrets. This may discard useful endpoint details. Labels, unstructured prose, names, unusual hostnames, addresses, financial/medical/customer data, proprietary code, encoded payloads and unrecognized secrets require explicit sensitive literals and human review. Malicious instructions in logs are not neutralized by redaction; treat uploaded logs as untrusted data.

Timestamps, severity, event IDs and hexadecimal diagnostic codes are generally retained, but heuristic matching can still over-redact versions, numbers, paths or diagnostic content. Literal replacements and overlapping categories can assign different aliases to the same identity in different representations. No claim is made that semantic identity resolution or complete PII detection is possible with these patterns.

Before upload, inspect **every output**, including its filename, for residual sensitive data, lost context and malformed structure. Never upload the input, sensitive-values file, or any local identity list. Follow your organization's disclosure policy.

## Validation status

A smoke test is provided for actual PowerShell execution. The authoring environment had no PowerShell runtime and its download proxy was unavailable, so the smoke test and Windows/Office format checks have **not been executed**. Runtime functionality is unconfirmed. Run the test above on PowerShell 7.2+ and validate representative organization-specific fixtures before operational use.
