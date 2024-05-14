#!/usr/bin/env python3
import qiling
import sys

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <ELF>")
        sys.exit(1)
    cmd = [sys.argv[1]]
    ql = qiling.Qiling(cmd, console=False, rootfs='.')
    ql.run()