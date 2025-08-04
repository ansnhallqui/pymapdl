import subprocess
import psutil
import sys
import os
import time

sys.argv.pop(0)
r = subprocess.Popen(sys.argv)
term = open("/dev/tty","w")
sys.stdout = term
sys.stderr = term
while r.poll() is None:
    if os.getppid() == 1:
        for proc in psutil.Process().children(recursive = True):
            proc.kill()
    time.sleep(0.1)
