"""Build the release ZIP for WordPress Security Plugin.

Only the files that belong on a live site go in: no Git metadata, no tests, no documentation drafts and nothing
that could hold a credential. The resulting ZIP is what gets attached to a GitHub release as wordpress-security-plugin.zip, and
the in-WordPress updater verifies its SHA-256 before installing anything.
"""
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED
import hashlib
import re

root = Path(__file__).resolve().parents[1]
output = root / 'dist' / 'wordpress-security-plugin.zip'
output.parent.mkdir(exist_ok=True)

main = root / 'wordpress-security-plugin.php'
version = re.search(r'^\s*\*\s*Version:\s*([\d.]+)\s*$', main.read_text(encoding='utf-8'), re.M)
if not version:
    raise ValueError('Could not read the Version header from wordpress-security-plugin.php')

files = [main, root / 'readme.txt']
files.extend(path for path in (root / 'includes').rglob('*.php') if path.is_file())

assets = root / 'assets'
if assets.is_dir():
    files.extend(path for path in assets.rglob('*') if path.is_file())

for file in files:
    if not file.exists():
        raise ValueError('Missing file in distribution: ' + str(file))
    relative = file.relative_to(root)
    if any(part.startswith('.') for part in relative.parts):
        raise ValueError('Hidden path in distribution: ' + str(relative))
    if file.suffix.lower() in ('.key', '.pem', '.pfx', '.p12', '.env'):
        raise ValueError('Possible credential in distribution: ' + str(relative))
    if re.search(r'(github_pat_|ghp_|gho_|ghs_|ghu_)[A-Za-z0-9_]{20}', file.read_text(encoding='utf-8', errors='ignore')):
        raise ValueError('A token-shaped string is present in: ' + str(relative))

with ZipFile(output, 'w', ZIP_DEFLATED) as archive:
    for file in sorted(files):
        archive.write(file, Path('wordpress-security-plugin') / file.relative_to(root))

digest = hashlib.sha256(output.read_bytes()).hexdigest()
print('Built:   ', output)
print('Version: ', version.group(1))
print('Files:   ', len(files))
print('SHA-256: ', digest)
print()
print('Release with:')
print(f'  gh release create v{version.group(1)} "{output}" --repo aliameenco-creator/wordpress-security-plugin --title "v{version.group(1)}" --notes "..."')
