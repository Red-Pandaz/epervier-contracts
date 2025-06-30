from pathlib import Path
import sys

project_root = Path(__file__).resolve().parents[4]  # epervier-registry
sys.path.insert(0, str(project_root / "ETHFALCON" / "python-ref")) 