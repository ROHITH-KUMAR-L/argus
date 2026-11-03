
import subprocess, sys, threading
def test_child_and_grandchild():
    code = "import subprocess,sys;print(subprocess.run([sys.executable,'-c','print(42)'],capture_output=True,text=True).stdout.strip())"
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert out.stdout.strip() == "42"
def test_thread():
    r = []
    t = threading.Thread(target=r.append, args=(1,)); t.start(); t.join()
    assert r == [1]
