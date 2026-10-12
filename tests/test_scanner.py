import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from scanner import scan_working_tree
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "samples"))
from build_vulnerable import build_source

ROOT = Path(__file__).resolve().parent.parent / "samples"


def categories(found):
    return [c for (_f, _l, _rule, c, _r, _e) in found]


def test_vulnerable_is_flagged(tmp_path):
    vuln_file = tmp_path / "vulnerable.py"
    vuln_file.write_text(build_source())
    found = categories(scan_working_tree(str(vuln_file)))
    assert "aws" in found
    assert found.count("aws") == 2       # access key id + secret key
    assert "github" in found
    assert "slack" in found
    assert "google" in found
    assert "stripe" in found
    assert "jwt" in found
    assert "private_key" in found
    assert "generic" in found            # the password= assignment


def test_fixed_is_clean():
    found = scan_working_tree(str(ROOT / "fixed.py"))
    assert found == []
