"""Command-line entry point."""
import argparse
import json
from .scanner import analyze

def main():
    parser = argparse.ArgumentParser(description='RepoLens: analyze repository quality and obvious secret patterns')
    parser.add_argument('path', nargs='?', default='.', help='Repository directory')
    parser.add_argument('--json', action='store_true', help='Output machine-readable JSON')
    parser.add_argument('--min-score', type=int, default=0, help='Exit nonzero below this score')
    args = parser.parse_args()
    if not 0 <= args.min_score <= 100:
        parser.error('--min-score must be between 0 and 100')
    try:
        result = analyze(args.path)
    except (ValueError, OSError) as err:
        parser.error(str(err))
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"\nRepoLens • {result['name']} • {result['score']}/100")
        print(f"Files: {result['files']}  |  Code lines: {result['lines_of_code']}")
        for finding in result['findings']:
            where = f" ({finding['file']}:{finding.get('line', '?')})" if 'file' in finding else ''
            print(f"- [{finding['severity'].upper()}] {finding['title']}{where}: {finding['detail']}")
        if not result['findings']:
            print('No issues flagged by the implemented checks.')
        for warning in result['warnings']:
            print(f'Warning: {warning}')
    return 1 if result['score'] < args.min_score else 0

if __name__ == '__main__':
    raise SystemExit(main())
