"""Build the standalone WordPress plugin without bundling visitor data."""
from pathlib import Path
import re
from zipfile import ZipFile, ZIP_DEFLATED

root = Path(__file__).resolve().parent
plugin = root / "is-this-an-agent"
version = re.search(r"^ \* Version: (\S+)$", (plugin / "is-this-an-agent.php").read_text(), re.M)[1]
constant = re.search(r"const VERSION = '([^']+)'", (plugin / "includes/Plugin.php").read_text())[1]
if version != constant:
    raise SystemExit(f"Plugin header {version} does not match Plugin::VERSION {constant}")
target = root.parent / "dist" / f"is-this-an-agent-{version}.zip"
files = [
    "is-this-an-agent.php",
    "uninstall.php",
    "README.md",
    "includes/Detector.php",
    "includes/Repository.php",
    "includes/Plugin.php",
    "assets/admin.css",
]
target.parent.mkdir(exist_ok=True)
with ZipFile(target, "w", ZIP_DEFLATED) as archive:
    for name in files:
        archive.write(plugin / name, "is-this-an-agent/" + name)
print(target)
