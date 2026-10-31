"""Heuristic repository checks. Not a substitute for a security audit."""
from __future__ import annotations
import os
import re
from pathlib import Path

SKIP_DIRS = {'.git', 'node_modules', '.venv', 'venv', '__pycache__', 'dist', 'build', '.next'}
CODE_EXTS = {'.py', '.js', '.ts', '.jsx', '.tsx', '.go', '.rs', '.java', '.rb', '.php'}
TEXT_EXTS = CODE_EXTS | {'.md', '.json', '.toml', '.yaml', '.yml', '.env', '.txt', '.sh', '.ini'}
MAX_FILES = 3000
MAX_BYTES = 512_000
SECRET_RULES = [
    ('Private key', re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----')),
    ('AWS access key identifier', re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b')),
    ('GitHub token', re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b')),
    ('Potential hardcoded credential', re.compile(r'(?i)\b(?:api_key|secret_key|password|token)\s*[:=]\s*["\'](?!example|changeme|placeholder|test)[^"\'\s]{12,}["\']')),
]

def analyze(root: str | Path) -> dict:
    root = Path(root).expanduser().resolve()
    if not root.is_dir():
        raise ValueError('Repository path must be an existing directory')
    files = []
    warnings = []
    truncated = False
    def walk_error(error):
        warnings.append('A directory could not be read; scan is incomplete.')
    for directory, dirs, filenames in os.walk(root, followlinks=False, onerror=walk_error):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS
                         and not Path(directory, d).is_symlink()
                         and not getattr(os.path, 'isjunction', lambda p: False)(Path(directory, d)))
        for filename in sorted(filenames):
            path = Path(directory, filename)
            if path.is_symlink() or not path.is_file():
                continue
            if len(files) == MAX_FILES:
                truncated = True
                break
            files.append(path)
        if truncated:
            break
    names = {p.name.lower() for p in files if p.parent == root}
    findings = []
    def add(level, title, detail, file=None, line=None):
        item = {'severity': level, 'title': title, 'detail': detail}
        if file is not None: item['file'] = str(file)
        if line is not None: item['line'] = line
        findings.append(item)
    if not any(n in names for n in ('readme.md', 'readme.rst', 'readme.txt')):
        add('medium', 'Missing README', 'Add setup, usage, and project goals to README.md')
    if not any(n in names for n in ('license', 'license.md', 'license.txt')):
        add('medium', 'Missing license', 'Add an open-source LICENSE file')
    if '.gitignore' not in names:
        add('medium', 'Missing .gitignore', 'Exclude secrets, dependency folders, and generated files')
    if not any({'test', 'tests', '__tests__'} & set(p.relative_to(root).parts[:-1])
               or p.name.startswith('test_') or p.name.endswith(('_test.py', '.test.js', '.test.ts', '.spec.js', '.spec.ts'))
               for p in files):
        add('medium', 'No obvious tests', 'Add automated unit tests and CI')
    if not any('.github/workflows/' in p.relative_to(root).as_posix() for p in files):
        add('low', 'No GitHub Actions workflow', 'Run tests automatically on pushes and pull requests')
    env_files = [p for p in files if p.name == '.env']
    for p in env_files:
        add('high', 'Environment file present', 'Verify .env is ignored and never committed', p.relative_to(root))
    lines_of_code = 0
    scanned = 0
    skipped = 0
    for path in files:
        if path.suffix.lower() not in TEXT_EXTS and path.name != '.env' and not path.name.startswith('.env.'):
            continue
        try:
            with path.open('rb') as source:
                content = source.read(MAX_BYTES + 1)
            if len(content) > MAX_BYTES:
                skipped += 1
                continue
            text = content.decode('utf-8')
        except (UnicodeError, OSError):
            skipped += 1
            continue
        scanned += 1
        rel = path.relative_to(root).as_posix()
        if path.suffix.lower() in CODE_EXTS:
            lines_of_code += sum(bool(line.strip()) for line in text.splitlines())
        for number, line in enumerate(text.splitlines(), 1):
            for label, pattern in SECRET_RULES:
                if pattern.search(line):
                    add('high', label, 'Review this line for leaked credentials. Never post real secrets in issue reports.', rel, number)
                    break
            if len(line) > 180 and path.suffix.lower() in CODE_EXTS:
                # Limit noise to one long-line finding per file.
                if not any(f.get('file') == rel and f['title'] == 'Very long line' for f in findings):
                    add('low', 'Very long line', 'Consider formatting code for readability', rel, number)
    penalty = {'high': 20, 'medium': 8, 'low': 3}
    score = max(0, 100 - sum(penalty[f['severity']] for f in findings))
    if truncated:
        warnings.append(f'File limit ({MAX_FILES}) reached; scan is incomplete.')
    if skipped:
        warnings.append(f'{skipped} text files skipped: too large, unreadable, or not UTF-8.')
    return {'name': root.name, 'score': score, 'files': len(files), 'scanned_text_files': scanned,
            'warnings': warnings, 'truncated': truncated, 'skipped_text_files': skipped,
            'lines_of_code': lines_of_code, 'findings': findings,
            'disclaimer': 'Heuristic checks only; not a comprehensive security audit. Files are processed locally.'}
