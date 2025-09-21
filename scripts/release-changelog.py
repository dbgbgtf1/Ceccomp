#!/usr/bin/python3
import sys
import re
CHANGELOG = 'CHANGELOG.md'

if len(sys.argv) < 2:
    print(f'Usage: python {sys.argv[0]} <TAG>', file=sys.stderr)
    sys.exit(1)

tag = sys.argv[1]
if not re.match(r'v\d+\.\d+(\.\d+)?', tag):
    print(f'The tag {tag} does not match the rule vX.X or vX.X.X', file=sys.stderr)
    sys.exit(1)

version = tag[1:]
print(f'Locating version {version} in {CHANGELOG}', file=sys.stderr)

pattern_version = re.compile(rf'^##\s*{re.escape(version)}\s*')
pattern_header = re.compile(r'^##\s*')

lines = None
try:
    with open(CHANGELOG) as f:
        lines = f.readlines()
except OSError as e:
    print(f'Failed to read file {CHANGELOG}: {e}')
    sys.exit(1)

capturing = False
for line in lines:
    if not capturing:
        # mark if found the target version section
        if pattern_version.match(line.strip()):
            capturing = True
    else:
        # print the whole line if the line is not next version section
        if pattern_header.match(line.strip()):
            break
        print(line, end='') # already containing a '\n'

if not capturing: # no match
    print(f'No match version section for {version}', file=sys.stderr)
    sys.exit(1)
