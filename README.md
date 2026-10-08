# Duplicate File Finder

Find repeated file content in a directory you choose. This small, read-only Python utility groups files by size and SHA-256 content hash, reports redundant logical bytes, and writes a clear HTML or JSON report. **There is no delete command.**

**Status: working prototype, created with substantial AI assistance.** It has automated tests but no independent field trial or measured adoption. It does not measure environmental impact or promise disk-space savings.

## Run it

You need **Python 3.9 or newer**. No dependencies, account, network connection, or installation is required. Download the files, open a terminal in this folder, and choose an explicit directory:

```sh
python3 dupfinder.py /path/to/your/folder
python3 dupfinder.py /path/to/your/folder --html report.html --json report.json
```

On Windows, use `py -3` instead of `python3` if needed. Quote paths containing spaces. Open `report.html` in a browser. Reports use no external assets, scripts, or tracking.

Each output must be a **new filename in an existing folder**. Existing files, symbolic links, and hardlink aliases cannot be overwritten. You can put a new report inside the scan directory; it is not part of that scan. A later scan will treat old reports as ordinary files. If one output succeeds and another cannot be written, the completed output may remain and the command reports an error.

## What is counted

- The scanner recursively visits regular files, including hidden files, under the chosen directory. Symbolic links, including directory links, are skipped. A symbolic link cannot be the scan root.
- Files of a unique size do not need hashing. Same-size candidates are read in 1 MiB chunks. SHA-256 matches form a content group; no byte-by-byte second comparison is performed.
- Hardlinks refer to the same underlying file and are counted once. Aliases appear next to that file in duplicate groups.
- For `n` distinct files of `s` bytes with identical hashes, redundant logical bytes are `(n − 1) × s`. Three separate 6-byte copies therefore count as **12 redundant bytes**. Empty duplicate files count as zero bytes.
- Logical bytes are not guaranteed reclaimable storage: compression, sparse files, clones, filesystem metadata, and backups can change actual space use.
- Identity, size, modification time, and change time are checked before and after hashing. Detected changes, inaccessible paths, and read failures are listed as skipped. Results are a snapshot, and files can change afterward. This is a convenience scanner, not a forensic integrity or adversarial security tool.

Review every group before doing anything with files. Identical content does not mean a file is unnecessary: different applications or projects may require their own copies.

## Privacy

Scanning and reporting stay local. Reports contain the scan root and filenames, which may be private; inspect them before sharing. No personal file samples are bundled. Tests create synthetic content in temporary directories.

## Development

```sh
python3 -m unittest -v test_dupfinder
```

Tests cover multi-copy arithmetic, empty files, size filtering, hardlinks, symbolic links and loops, changed-file detection before/during hashing, read errors, safe HTML/terminal output, output collision protection, and report files inside the scan tree. Hosted checks are defined in [the GitHub Actions workflow](.github/workflows/tests.yml); see the repository’s Actions tab for their latest result.

Built: directory scanning, content groups, skipped-file reporting, and text/JSON/HTML reports. Not implemented: deletion, automatic cleanup, byte-by-byte comparison, persistent indexing, cloud storage, or measured environmental benefits.

## Contributing and license

Small correctness fixes and reproducible bug reports are welcome. Use synthetic files in reports and tests; never upload someone else's files or private paths. Describe the Python version, operating system, expected behavior, and observed behavior.

[MIT](LICENSE). Independent project; no subscription-program affiliation.
