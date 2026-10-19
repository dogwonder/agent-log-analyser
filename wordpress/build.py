"""Build the standalone WordPress plugin without bundling visitor data."""
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED

root = Path(__file__).resolve().parent
plugin = root / "is-this-an-agent"
target = root.parent / "dist" / "is-this-an-agent-0.1.1.zip"
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
