#!/usr/bin/python3
import re
import sys
import os

CHANGELOG = 'CHANGELOG.md'
DEFAULT_REPO = 'dbgbgtf1/Ceccomp'

# 匹配三种引用情况：#123, !456, user/repo#789, user/repo!456
pattern = re.compile(r'(?:\s+)((?:[\w.-]+/[\w.-]+)?[#!]\d+)$')


def convert(token: str) -> str:
    """根据匹配到的 token 转换成对应的 Markdown 链接"""
    repo = DEFAULT_REPO

    if '#' in token:
        if '/' in token.split('#')[0]:
            repo, number = token.split('#', 1)
        else:
            number = token[1:]
        return f'  :link: [{token}](https://github.com/{repo}/issues/{number})'

    if '!' in token:
        if '/' in token.split('!')[0]:
            repo, number = token.split('!', 1)
        else:
            number = token[1:]
        return f'  :link: [{token}](https://github.com/{repo}/pulls/{number})'

    assert False, f'Token {token} does not match any case, what the hack?'


def main():
    if not os.path.isdir('.git'):
        print('Please goto repo root first', file=sys.stderr)
        sys.exit(2)
    is_check = len(sys.argv) > 1 and sys.argv[1] == '--check'
    has_match = False

    with open(CHANGELOG) as f:
        lines = f.readlines()

    output_lines = []
    for lineno, line in enumerate(lines, start=1):
        m = pattern.search(line)
        if m:
            token = m.group(1)
            new_line = line[: m.start(1)].rstrip() + '\n'
            converted = convert(token)

            if is_check:
                print(f'[line {lineno}] found: {token}')
                has_match = True
            else:
                output_lines.append(new_line)
                output_lines.append(converted + '\n')
        elif not is_check:
            output_lines.append(line)

    if not is_check:
        with open(CHANGELOG, 'w') as f:
            f.writelines(output_lines)

    # --check 模式下，若发现可转换内容，则退出码设为1
    if is_check and has_match:
        sys.exit(1)


if __name__ == '__main__':
    main()
