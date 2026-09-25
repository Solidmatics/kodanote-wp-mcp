#!/usr/bin/env python3
"""Build an uploadable WordPress plugin ZIP without dev fixtures or dependencies."""
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED

root = Path(__file__).resolve().parents[1]
output = root / 'dist' / 'kodanote-mcp-0.3.0.zip'
output.parent.mkdir(exist_ok=True)
files = [root / name for name in ('kodanote-mcp.php', 'uninstall.php', 'readme.txt', 'README.md', 'LICENSE')]
files += sorted((root / 'includes').glob('*.php'))
with ZipFile(output, 'w', ZIP_DEFLATED) as archive:
    for file in files:
        archive.write(file, Path('kodanote-mcp') / file.relative_to(root))
print(output)
