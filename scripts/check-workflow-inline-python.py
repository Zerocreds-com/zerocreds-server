"""Syntax-check Python heredocs used by production operations workflows."""

from pathlib import Path


for name in (
    '.github/workflows/production-readiness.yml',
    '.github/workflows/provision-admin-token.yml',
):
    source = Path(name).read_text()
    marker = "<<'PY'\n"
    if source.count(marker) != 1:
        raise SystemExit(f'{name}: expected exactly one Python heredoc')
    block = source.split(marker, 1)[1].split('            PY', 1)[0]
    code = '\n'.join(line[12:] for line in block.splitlines())
    compile(code, name, 'exec')
