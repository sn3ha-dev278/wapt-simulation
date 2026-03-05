# Issue #06 — PDF Metadata Disclosure Leaks Author and Tooling Information

| Field         | Details                                          |
|---------------|--------------------------------------------------|
| **Target**    | BankWeb — `http://localhost:1337/docs/`          |
| **Severity**  | Low                                              |
| **CVSS v3.1** | 3.1                                              |
| **Vector**    | AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N             |
| **Category**  | Information Disclosure                           |

---

## Summary

The PDF files served through the publicly accessible `/docs/` directory (Issue #02) retain their original document metadata. This metadata, embedded in the files at creation time and extractable with standard tools, exposes the names of internal personnel who authored the documents, the software used to produce them, internal document identifiers, and creation timestamps. While individually low-severity, this information contributes to a broader reconnaissance picture and may facilitate social engineering or targeted attacks against identified individuals.

---

## Steps to Reproduce

1. Download the PDF files from the exposed directory listing (see Issue #02):

   ```bash
   wget http://localhost:1337/docs/legal.pdf
   wget http://localhost:1337/docs/[REDACTED-FILENAME].pdf
   ```

2. Extract the embedded metadata using `exiftool`:

   ```bash
   exiftool legal.pdf
   exiftool [REDACTED-FILENAME].pdf
   ```

3. Observe that the output contains author names, creation tool details, internal document UUIDs, and original creation/modification timestamps.

---

## Proof of Concept

### `legal.pdf` — Metadata Extract

```
ExifTool Version Number         : 13.25
File Size                       : 145 kB
File Type                       : PDF
PDF Version                     : 1.7
Page Count                      : 4
Language                        : en-US
XMP Toolkit                     : 3.1-701
Creator Tool                    : Microsoft Word
Create Date                     : 2020:09:30 23:34:05-07:00
Modify Date                     : 2020:09:30 23:34:05-07:00
Document ID                     : [REDACTED-UUID]
Instance ID                     : [REDACTED-UUID]
Author                          : [REDACTED-AUTHOR]
Creator                         : [REDACTED-AUTHOR]
```

### `[REDACTED-FILENAME].pdf` — Metadata Extract

```
ExifTool Version Number         : 13.25
File Size                       : 3.3 kB
File Type                       : PDF
PDF Version                     : 1.4
Page Count                      : 1
Producer                        : GPL Ghostscript 8.15
Create Date                     : 2015:08:14 14:57:52
Modify Date                     : 2015:08:14 14:57:52
Title                           : Microsoft Word - [REDACTED]
Creator                         : PScript5.dll Version 5.2.2
Author                          : [REDACTED-AUTHOR]
```

> **Note:** Author names, document UUIDs, internal file titles, and the internal meeting document filename have been redacted in this report. The full values were confirmed present in the extracted metadata during testing.

---

## Impact

- **Personnel enumeration** — author names extracted from document metadata can be used to identify real employees of the organisation, providing a starting point for phishing, spear-phishing, or credential stuffing attacks against corporate accounts.
- **Tooling and versioning disclosure** — the presence of specific software versions (e.g. `GPL Ghostscript 8.15`, `PScript5.dll Version 5.2.2`, `Microsoft Word`) reveals the internal toolchain. Older versions may be associated with known CVEs that could be leveraged in client-side attacks.
- **Internal document structure exposure** — the `Title` field in one document retains the original working filename (e.g. `Microsoft Word - Dokument1`), suggesting documents were exported without any sanitisation step, which may hint at broader operational security gaps.
- **Temporal intelligence** — original creation dates reveal when documents were produced internally, which may contradict public statements or expose development timelines that an attacker could exploit for social engineering purposes.
- **Compound risk with Issue #02** — the metadata disclosure is only reachable because directory listing is enabled (Issue #02). Remediating that issue would eliminate the unauthenticated access path, but the metadata should be stripped regardless in case the files are exposed through other means in future.

---

## Recommended Mitigations

1. **Strip metadata from all documents before publishing.** Use `exiftool` or equivalent tooling as part of the document preparation workflow:

   ```bash
   # Strip all metadata in-place
   exiftool -all= legal.pdf
   exiftool -all= privacy_policy.pdf

   # Verify the result
   exiftool legal.pdf
   ```

2. **Automate metadata sanitisation in the deployment pipeline.** Any document destined for public serving should pass through a metadata-stripping step before being placed in the web root, preventing future regressions:

   ```bash
   # Example pre-deploy script
   find ./wwwroot/docs -name "*.pdf" -exec exiftool -all= {} \;
   ```

3. **Address the root cause — directory listing.** As noted in Issue #02, the `/docs/` directory should not be browseable at all. Disabling directory listing and restricting access to explicitly intended public files eliminates the primary access vector for this finding.

4. **Establish a document publication policy** that requires metadata review before any file is committed to a publicly accessible location. This should cover PDFs, Office documents, and image files, all of which commonly retain authorship and tooling metadata.