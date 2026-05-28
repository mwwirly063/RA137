"""
Centralized path and output-folder management for RA137.

Provides helpers to create the standard output directory tree and
per-target directories.
"""

from pathlib import Path
from typing import Dict


# ---------------------------------------------------------------------------
# Standard output sub-folders
# ---------------------------------------------------------------------------
_OUTPUT_SUBFOLDERS = (
    "cdn",
    "realip",
    "tech",
    "vulns",
    "network",
    "final",
    "logs",
)


def create_output_structure(base_dir: Path = Path("outputs")) -> Dict[str, Path]:
    """
    Create the centralised output directory tree and return a mapping.

    ::

        outputs/
        ├── cdn/
        ├── realip/
        ├── tech/
        ├── vulns/
        ├── network/
        ├── final/
        └── logs/
    """
    folders: Dict[str, Path] = {"base": base_dir}
    for name in _OUTPUT_SUBFOLDERS:
        folders[name] = base_dir / name

    for folder in folders.values():
        folder.mkdir(parents=True, exist_ok=True)

    return folders


def create_target_output(target: str, base_dir: Path = Path("outputs")) -> Path:
    """
    Create (and return) a per-target output directory with all sub-folders.

    Strips protocol prefixes and replaces ``/`` with ``_`` so the name
    is safe to use as a directory name.

    Structure::

        outputs/<target>/
        ├── cdn/
        ├── realip/
        ├── tech/
        ├── vulns/
        ├── network/
        ├── final/
        └── logs/
    """
    clean = (
        target
        .replace("https://", "")
        .replace("http://", "")
        .replace("/", "_")
    )
    target_dir = base_dir / clean
    target_dir.mkdir(parents=True, exist_ok=True)

    # Create category sub-folders inside the target directory
    for name in _OUTPUT_SUBFOLDERS:
        (target_dir / name).mkdir(parents=True, exist_ok=True)

    return target_dir


def get_output_paths(target_dir: Path) -> Dict[str, Path]:
    """Return standard output *file* paths for a per-target directory."""
    return {
        "cdn_analysis":     target_dir / "cdn"     / "cdn_analysis.json",
        "realip_results":   target_dir / "realip"  / "realip_results.json",
        "asn_results":     target_dir / "realip"  / "asn_results.json",
        "final_ips":        target_dir / "final"   / "final_ip.txt",
        "tech_results":     target_dir / "tech"    / "tech_results.json",
        "network_results":  target_dir / "network" / "network_results.json",
        "vuln_results":     target_dir / "vulns"   / "vuln_results.json",
    }