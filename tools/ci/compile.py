import subprocess
import pathlib
import sys

tmpfile = pathlib.Path('temp.bin')
cmd = ['yarac'] + sys.argv[1:] + [str(tmpfile.absolute())]

ERROR = -1
try:
    process = subprocess.run(cmd, check=False)
    ERROR = process.returncode

    if not tmpfile.exists():
        print(f'[COMPILER] Compiled file wasnt created: {str(tmpfile)}')
        # ERROR = -2
except Exception as e:
    print(f'[COMPILER] Process Exception happened: {e}')

try:
    tmpfile.unlink()
except Exception as e:
    pass

if ERROR != 0:
    print(f'[COMPILER] returned error! cmd: {cmd}')

sys.exit(ERROR)
