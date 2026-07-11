from __future__ import annotations

import pathlib
import sys
import time

source = pathlib.Path(sys.argv[1])
done = pathlib.Path(sys.argv[2])
position = 0
while True:
    try:
        with source.open("rb") as stream:
            stream.seek(position)
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    break
                sys.stdout.buffer.write(chunk)
                sys.stdout.buffer.flush()
            position = stream.tell()
    except FileNotFoundError:
        pass
    if done.exists():
        break
    time.sleep(0.05)
