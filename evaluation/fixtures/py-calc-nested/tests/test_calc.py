
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
from calc import add
def test_add():
    assert add(2, 3) == 5
