import os
import sys
from pathlib import Path
import stat

def main():
    bin_path = Path(__file__).parent / "ceccomp"
    os.chmod(bin_path, os.stat(bin_path).st_mode | stat.S_IEXEC)
    os.execv(bin_path, [str(bin_path)] + sys.argv[1:])

if __name__ == "__main__":
    main()
