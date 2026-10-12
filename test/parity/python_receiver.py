"""Runs the Python receiver on EGTS packets and compares its documents with ours.

Usage: python python_receiver.py <path to gazpromneft_receiver/src>

Reads {"cases": [{"name", "address": [ip, port], "packets": [hex], "go_docs": [hex]}]}
from stdin. Each case is one connection. Both sides' documents are decoded with
the receiver's own utils/pack.py, as the consumers do, and compared without
date_create. Prints {"<case>": ["<difference>", ...]}.
"""

import json
import logging
import sys
import types
from collections import deque


def stub_tornado():
    class IOLoop:
        @classmethod
        def instance(cls):
            return cls()

        def add_timeout(self, *args):
            return None

        def remove_timeout(self, *args):
            pass

    tornado = types.ModuleType('tornado')
    ioloop = types.ModuleType('tornado.ioloop')
    ioloop.IOLoop = IOLoop
    tornado.ioloop = ioloop
    sys.modules['tornado'] = tornado
    sys.modules['tornado.ioloop'] = ioloop


class Stream:
    """tornado.iostream.IOStream fed from a buffer. Callbacks run from a queue
    after the current one returns, as they would on the IOLoop."""

    def __init__(self, data):
        self.data = data
        self.pending_read = None
        self.callbacks = deque()
        self.is_closed = False

    def read_bytes(self, n, callback):
        self.pending_read = (n, callback)

    def read_until(self, delimiter, callback, max_bytes=None):
        raise NotImplementedError

    def write(self, data, callback=None):
        if callback:
            self.callbacks.append(callback)

    def closed(self):
        return self.is_closed

    def close(self):
        self.is_closed = True

    def set_close_callback(self, callback):
        pass

    def run(self):
        while not self.is_closed:
            if self.callbacks:
                self.callbacks.popleft()()
                continue
            if self.pending_read is None or len(self.data) < self.pending_read[0]:
                return
            (n, callback), self.pending_read = self.pending_read, None
            chunk, self.data = self.data[:n], self.data[n:]
            callback(chunk)


class Redis:
    def __init__(self):
        self.lists = {}

    def incr(self, *args):
        pass

    def decr(self, *args):
        pass

    def ltrim(self, *args):
        pass

    def lpush(self, key, value):
        self.lists.setdefault(key, []).insert(0, value)

    def pipeline(self):
        return self

    def execute(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def run_python_receiver(Egts, address, data):
    """Does what server.StreamWorker does for one connection."""
    stream = Stream(data)
    redis = Redis()
    logger = logging.getLogger('python-receiver')

    def get_protocol(signature):
        if signature[0] != Egts.SIGNATURE:
            stream.close()
            return
        stream.read_bytes(Egts.HEADER_SIZE - 2, Egts(stream, redis, logger, signature, list(address)).read)

    stream.read_bytes(2, get_protocol)
    stream.run()
    # LPUSH puts the newest first; return them in push order.
    return list(reversed(redis.lists.get('charger', [])))


def differences(path, python, go):
    if isinstance(python, dict) and isinstance(go, dict):
        diffs = []
        for key in sorted(set(python) | set(go), key=str):
            if key not in go:
                diffs.append(f'{path}.{key}: missing in Go (Python: {python[key]!r})')
            elif key not in python:
                diffs.append(f'{path}.{key}: not in Python (Go: {go[key]!r})')
            else:
                diffs += differences(f'{path}.{key}', python[key], go[key])
        return diffs
    if isinstance(python, list) and isinstance(go, list) and len(python) == len(go):
        return [d for i, (p, g) in enumerate(zip(python, go)) for d in differences(f'{path}[{i}]', p, g)]
    if type(python) is not type(go) or python != go:
        return [f'{path}: Python {python!r}, Go {go!r}']
    return []


def main():
    sys.path.insert(0, sys.argv[1])
    stub_tornado()
    import utils
    utils.get_ip_last_number = lambda: '0'
    from protocols.egts import Egts
    from utils.pack import loads

    logging.disable(logging.CRITICAL)

    result = {}
    for case in json.load(sys.stdin)['cases']:
        data = b''.join(bytes.fromhex(p) for p in case['packets'])
        python_docs = [loads(d) for d in run_python_receiver(Egts, case['address'], data)]
        go_docs = [loads(bytes.fromhex(d)) for d in case['go_docs']]
        for doc in python_docs + go_docs:
            doc.pop('date_create', None)

        if len(python_docs) != len(go_docs):
            result[case['name']] = [f'Python made {len(python_docs)} documents, Go {len(go_docs)}']
        else:
            result[case['name']] = [d for i, (p, g) in enumerate(zip(python_docs, go_docs))
                                    for d in differences(f'doc[{i}]', p, g)]
    json.dump(result, sys.stdout)


if __name__ == '__main__':
    main()
