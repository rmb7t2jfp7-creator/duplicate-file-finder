"""Read-only duplicate content finder. Python 3.9+, standard library only."""
import argparse
from collections import defaultdict
from dataclasses import dataclass
from html import escape
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

CHUNK_SIZE = 1024 * 1024


class ChangedFileError(OSError):
    """A file no longer matches the snapshot collected for this scan."""


@dataclass
class Candidate:
    path: Path
    snapshot: os.stat_result
    aliases: list


def _signature(value):
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _hash_file(candidate):
    """Hash in bounded chunks, checking identity and metadata before and after."""
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(candidate.path, flags)
    with os.fdopen(fd, 'rb') as handle:
        if _signature(os.fstat(handle.fileno())) != _signature(candidate.snapshot):
            raise ChangedFileError('changed before hashing')
        digest = hashlib.sha256()
        while True:
            chunk = handle.read(CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(handle.fileno())
    current = candidate.path.lstat()
    if not stat.S_ISREG(current.st_mode) or _signature(after) != _signature(candidate.snapshot) or _signature(current) != _signature(candidate.snapshot):
        raise ChangedFileError('changed during hashing')
    return digest.hexdigest()


def scan(directory, exclude=()):
    supplied = Path(directory).absolute()
    if supplied.is_symlink():
        raise ValueError('The scan root must be a real directory, not a symbolic link.')
    root = supplied.resolve(strict=True)
    if not root.is_dir():
        raise ValueError('The scan root must be a directory.')
    excluded = {Path(path).absolute() for path in exclude}
    candidates = {}
    skipped = []
    seen_files = 0
    stack = [root]

    def relative(path):
        return str(path.relative_to(root))

    def skip(path, reason):
        skipped.append({'path': relative(path), 'reason': reason})

    while stack:
        folder = stack.pop()
        try:
            if folder.is_symlink():
                skip(folder, 'symbolic link directory not followed')
                continue
            with os.scandir(folder) as iterator:
                children = sorted(iterator, key=lambda child: child.name)
        except OSError as exc:
            skip(folder, 'cannot read directory: ' + str(exc))
            continue
        for child in children:
            path = Path(child.path)
            if path.absolute() in excluded:
                continue
            try:
                snapshot = child.stat(follow_symlinks=False)
                if stat.S_ISLNK(snapshot.st_mode):
                    skip(path, 'symbolic link not followed')
                elif stat.S_ISDIR(snapshot.st_mode):
                    stack.append(path)
                elif stat.S_ISREG(snapshot.st_mode):
                    seen_files += 1
                    identity = (snapshot.st_dev, snapshot.st_ino)
                    if identity in candidates:
                        candidates[identity].aliases.append(path)
                    else:
                        candidates[identity] = Candidate(path, snapshot, [])
                else:
                    skip(path, 'not a regular file')
            except OSError as exc:
                skip(path, 'cannot inspect file: ' + str(exc))
    sizes = defaultdict(list)
    for candidate in candidates.values():
        sizes[candidate.snapshot.st_size].append(candidate)
    groups = []
    hashed = 0
    for size, entries in sizes.items():
        if len(entries) < 2:
            continue
        digests = defaultdict(list)
        for candidate in entries:
            try:
                digest = _hash_file(candidate)
                digests[digest].append(candidate)
                hashed += 1
            except OSError as exc:
                skip(candidate.path, 'skipped hashing: ' + str(exc))
        for digest, matches in digests.items():
            if len(matches) < 2:
                continue
            files = sorted(({'path': relative(item.path), 'hardlink_aliases': sorted(relative(alias) for alias in item.aliases)} for item in matches), key=lambda item: item['path'])
            groups.append({'sha256': digest, 'bytes_per_file': size, 'distinct_files': len(files), 'redundant_bytes': size * (len(files) - 1), 'files': files})
    groups.sort(key=lambda group: (-group['redundant_bytes'], group['files'][0]['path']))
    return {
        'schema_version': 1,
        'tool': 'Duplicate File Finder',
        'root': str(root),
        'files_seen': seen_files,
        'distinct_files_seen': len(candidates),
        'hardlink_alias_count': seen_files - len(candidates),
        'files_hashed': hashed,
        'duplicate_groups': len(groups),
        'redundant_bytes': sum(group['redundant_bytes'] for group in groups),
        'groups': groups,
        'skipped': sorted(skipped, key=lambda item: item['path']),
        'limitations': [
            'Read-only snapshot. No files were deleted or modified. Review duplicates yourself.',
            'Redundant bytes means logical file bytes beyond one distinct file per group, not guaranteed disk space savings. Hardlink aliases are counted once.',
            'Only same-size candidates are hashed with SHA-256. Matching hashes are strong content evidence, not a mathematical proof; no byte-by-byte comparison is performed.',
            'Files can change after this scan. Detected changes and read errors are skipped, so results may be incomplete.',
            'Reports contain local paths and filenames. Review them before sharing. No environmental benefit is measured.',
        ],
    }


def text_report(report):
    lines = ['Duplicate File Finder', 'Read-only scan: ' + repr(report['root']), f"Duplicate groups: {report['duplicate_groups']}", f"Redundant logical bytes: {report['redundant_bytes']}", f"Regular file paths: {report['files_seen']}; hardlink aliases: {report['hardlink_alias_count']}; files hashed: {report['files_hashed']}"]
    for number, group in enumerate(report['groups'], 1):
        lines.extend(['', f"Group {number}: {group['distinct_files']} distinct files, {group['bytes_per_file']} bytes each", 'SHA-256: ' + group['sha256']])
        for item in group['files']:
            lines.append('  ' + repr(item['path']))
            for alias in item['hardlink_aliases']:
                lines.append('    hardlink alias: ' + repr(alias))
    for item in report['skipped']:
        lines.append('SKIPPED ' + repr(item['path']) + ': ' + repr(item['reason']))
    return '\n'.join(lines + [''] + report['limitations']) + '\n'


def html_report(report):
    safe = lambda value: escape(str(value), quote=True)
    groups = []
    for number, group in enumerate(report['groups'], 1):
        rows = ''.join('<li><code>' + safe(item['path']) + '</code>' + ("<br><small>Hardlink aliases: " + ', '.join(safe(alias) for alias in item['hardlink_aliases']) + '</small>' if item['hardlink_aliases'] else '') + '</li>' for item in group['files'])
        groups.append(f"<section><h2>Group {number}</h2><p>{group['distinct_files']} distinct files · {group['bytes_per_file']} bytes each · {group['redundant_bytes']} redundant logical bytes</p><ul>{rows}</ul><p class='digest'>SHA-256: {safe(group['sha256'])}</p></section>")
    skipped = ''.join('<li><code>' + safe(item['path']) + '</code>: ' + safe(item['reason']) + '</li>' for item in report['skipped'])
    limitations = ''.join('<li>' + safe(item) + '</li>' for item in report['limitations'])
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"><title>Duplicate File Finder report</title><style>body{{font:16px/1.6 system-ui,sans-serif;max-width:850px;margin:auto;padding:32px 20px;background:#f4f6fc;color:#25334d}}h1{{margin-bottom:0}}section{{padding:20px;border:1px solid #ccd3e2;border-radius:14px;background:white;margin:18px 0}}code,.digest{{overflow-wrap:anywhere}}.number{{font-size:2rem;font-weight:700}}li{{margin:8px 0}}small{{color:#536075}}</style></head><body><p>LOCAL UTILITIES / READ-ONLY</p><h1>Duplicate File Finder</h1><p>Scan root: <code>{safe(report['root'])}</code></p><section><div class="number">{report['duplicate_groups']} duplicate groups</div><p>{report['redundant_bytes']} redundant logical bytes · {report['hardlink_alias_count']} hardlink aliases counted once</p><p>No files deleted or modified.</p></section>{''.join(groups) or '<p>No duplicate content groups were found among readable candidates.</p>'}<section><h2>Skipped paths ({len(report['skipped'])})</h2><ul>{skipped or '<li>None</li>'}</ul></section><section><h2>Understand the results</h2><ul>{limitations}</ul></section></body></html>'''


def main(argv=None):
    parser = argparse.ArgumentParser(description='Find duplicate file content locally, without deleting anything.')
    parser.add_argument('directory', type=Path, help='explicit directory to scan recursively')
    parser.add_argument('--json', type=Path, metavar='FILE', help='write JSON to a new file')
    parser.add_argument('--html', type=Path, metavar='FILE', help='write standalone HTML to a new file')
    args = parser.parse_args(argv)
    outputs = [path for path in (args.json, args.html) if path is not None]
    try:
        if len({path.resolve() for path in outputs}) != len(outputs):
            raise ValueError('JSON and HTML output paths must differ.')
        for path in outputs:
            if path.exists() or path.is_symlink():
                raise ValueError('Refusing to overwrite an existing path: ' + str(path))
            if not path.parent.is_dir():
                raise ValueError('Output folder does not exist: ' + str(path.parent))
        report = scan(args.directory, exclude=outputs)
        content = []
        if args.json:
            content.append((args.json, json.dumps(report, ensure_ascii=True, indent=2) + '\n'))
        if args.html:
            content.append((args.html, html_report(report)))
        for path, rendered in content:
            with path.open('x', encoding='utf-8', errors='backslashreplace') as handle:
                handle.write(rendered)
        sys.stdout.write(text_report(report))
        return 0
    except (ValueError, OSError) as exc:
        print('Error: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
