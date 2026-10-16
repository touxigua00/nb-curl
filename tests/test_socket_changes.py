"""Socket 增量队列与 loop 注册回归；用 --backend 选择后端。"""
from __future__ import annotations

import argparse
import importlib
import os
from pathlib import Path
import socket
import sys
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch


class RecordingLoop:
    def __init__(self):
        self.calls = []
        self.closed = set()

    def add_reader(self, fd, callback, *args):
        if fd in self.closed:
            raise OSError("registered a closed fd")
        self.calls.append(("add_reader", fd))

    def add_writer(self, fd, callback, *args):
        if fd in self.closed:
            raise OSError("registered a closed fd")
        self.calls.append(("add_writer", fd))

    def remove_reader(self, fd):
        self.calls.append(("remove_reader", fd))

    def remove_writer(self, fd):
        self.calls.append(("remove_writer", fd))


class SocketChangesTests(unittest.TestCase):
    def setUp(self):
        self.core = importlib.import_module("nb_curl._stream_core")
        self.multi = importlib.import_module("nb_curl._multi")
        self.lib = importlib.import_module("nb_curl._native").lib
        self.driver = object.__new__(self.multi.AsyncDriver)
        self.driver.mode = "loop"
        self.driver.loop = RecordingLoop()
        self.driver._read_fds = set()
        self.driver._write_fds = set()
        self.driver._fd_actions = {}
        self.driver._fd_part = {}
        self.part = SimpleNamespace(multi=object(), broken=False)

    def sync(self, changes):
        with patch.object(self.core, "lib", SimpleNamespace(
                multi_socket_changes=lambda multi: changes)):
            self.driver._sync_sockets(self.part)

    def test_in_remove_never_registers_closed_fd(self):
        self.driver.loop.closed.add(17)
        self.sync([(17, 1), (17, 4)])
        self.assertEqual(self.driver.loop.calls, [])
        self.assertEqual(self.driver._fd_actions, {})
        self.assertEqual(self.driver._fd_part, {})

    def test_remove_in_reregisters_reused_fd(self):
        self.sync([(17, 1)])
        self.driver.loop.calls.clear()
        self.sync([(17, 4), (17, 1)])
        self.assertEqual(self.driver.loop.calls,
                         [("remove_reader", 17), ("add_reader", 17)])
        self.assertEqual(self.driver._read_fds, {17})
        self.assertEqual(self.driver._fd_actions, {17: 1})
        self.assertIs(self.driver._fd_part[17], self.part)

    def test_in_out_registers_only_final_writer(self):
        self.sync([(17, 1), (17, 2)])
        self.assertEqual(self.driver.loop.calls, [("add_writer", 17)])
        self.assertEqual(self.driver._read_fds, set())
        self.assertEqual(self.driver._write_fds, {17})
        self.assertEqual(self.driver._fd_actions, {17: 2})

    def test_broken_queue_fails_partition(self):
        self.driver._break_partition = unittest.mock.Mock()
        with patch.object(self.core, "lib", SimpleNamespace(
                multi_socket_changes=unittest.mock.Mock(side_effect=RuntimeError("broken")))):
            self.driver._sync_sockets(self.part)
        self.driver._break_partition.assert_called_once_with(self.part, -2)

    def test_socket_error_never_reads_timer_after_cleanup(self):
        core = object.__new__(self.core.PollCore)
        part = SimpleNamespace(multi=object(), broken=False, timer_at=None)
        core._shut = False
        core._parts = {"test": part}
        core._fd_actions = {}
        core._fd_part = {}
        freed = set()
        calls = []

        def timer(multi):
            self.assertNotIn(multi, freed, "timer accessed a released multi")
            calls.append("timer")
            return -1

        def cleanup(multi):
            self.assertNotIn(multi, freed, "multi freed twice")
            freed.add(multi)
            calls.append("cleanup")

        def break_partition(broken_part, rc):
            self.assertIs(broken_part, part)
            self.assertEqual(rc, -2)
            broken_part.broken = True
            fake.multi_cleanup(broken_part.multi)
            core._parts.clear()

        fake = SimpleNamespace(
            multi_active=lambda multi: 1,
            multi_timer=timer,
            multi_cleanup=cleanup,
            multi_socket_changes=unittest.mock.Mock(side_effect=RuntimeError("queue OOM")),
        )
        core._break_partition = break_partition
        with patch.object(self.core, "lib", fake):
            core._refresh_waits()
        self.assertTrue(part.broken)
        self.assertEqual(freed, {part.multi})
        self.assertEqual(calls.count("cleanup"), 1)

    def test_stream_remove_failure_finishes_all_siblings(self):
        streams = importlib.import_module("nb_curl._stream_reactor")
        reactor_class = next(cls for cls in vars(streams).values()
                             if isinstance(cls, type) and "_finish_job" in cls.__dict__)
        reactor = object.__new__(reactor_class)
        part = streams._StreamPartition("test", object())
        reactor._parts = {part.key: part}
        reactor._fd_actions = {}
        reactor._fd_part = {}
        reactor._by_reader = {}
        reactor._finish_stream_reader = unittest.mock.Mock()
        class Job(SimpleNamespace):
            __hash__ = object.__hash__
            __eq__ = object.__eq__

        jobs = []
        for i in range(3):
            handle = SimpleNamespace(ptr=i + 1, close=unittest.mock.Mock())
            reader = SimpleNamespace(
                _cond=threading.Condition(), _handle=handle, _done=False,
                _exc=None, _code=0, _error=None, _abort=False,
                _notify_locked=unittest.mock.Mock(),
                _release_event=threading.Event(), _release_handle=unittest.mock.Mock(),
            )
            job = Job(finished=False, state="ADDED", multi=part,
                      handle=handle, reader=reader, cancel_requested=False)
            jobs.append(job)
            reactor._by_reader[id(reader)] = job
            part.by_easy[handle.ptr] = job
        part.jobs = set(jobs)
        freed = set()

        def remove(multi, easy):
            self.assertNotIn(multi, freed, "remove accessed a released multi")
            return -2

        def cleanup(multi):
            self.assertNotIn(multi, freed, "multi freed twice")
            freed.add(multi)

        with patch.object(streams, "lib", SimpleNamespace(
                multi_remove=remove, multi_cleanup=cleanup)):
            reactor._finish_job(jobs[0])
        self.assertTrue(part.broken)
        self.assertEqual(freed, {part.multi})
        self.assertEqual(reactor._parts, {})
        self.assertEqual(reactor._by_reader, {})
        self.assertEqual(part.jobs, set())
        self.assertEqual(part.by_easy, {})
        for job in jobs:
            self.assertTrue(job.finished)
            self.assertIsNone(job.multi)
            self.assertTrue(job.reader._done)
            self.assertIsInstance(job.reader._exc, streams.RequestError)
            self.assertTrue(job.reader._release_event.is_set())
            job.reader._notify_locked.assert_called_once()
            job.reader._release_handle.assert_called_once()
            job.handle.close.assert_called_once()

    def test_native_queue_order_capacity_and_batch_cancel(self):
        self.assertEqual(self.lib.multi_abi_version(), 3)
        if not hasattr(self.lib, "_ffi"):
            self.skipTest("raw queue ABI is exercised with the cffi backend")
        ffi, native = self.lib._ffi, self.lib._c
        total = ffi.new("int *")
        handles, attached, accepted = [], [], []
        multi = self.lib.multi_init()
        self.assertTrue(multi)
        listener = socket.socket()
        try:
            listener.bind(("127.0.0.1", 0))
            listener.listen(8)
            listener.setblocking(False)
            peers = set()

            def transfer_fds(snapshot):
                found = set()
                for fd, _ in snapshot:
                    try:
                        sock = socket.socket(fileno=fd)
                    except OSError:
                        continue
                    try:
                        if sock.getsockname() in peers:
                            found.add(fd)
                    except OSError:
                        pass
                    finally:
                        sock.detach()
                return found

            url = ("http://127.0.0.1:%d/" % listener.getsockname()[1]).encode()
            for _ in range(3):
                easy = self.lib.easy_init()
                self.assertTrue(easy)
                handles.append(easy)
                self.assertEqual(self.lib.easy_set_url(easy, url), 0)
                self.assertEqual(self.lib.easy_set_proxy(easy, b""), 0)
                self.assertEqual(self.lib.easy_set_http_version(easy, 11), 0)
                self.assertEqual(self.lib.easy_set_timeout(easy, 5000), 0)
                self.assertEqual(self.lib.prepare_request(easy), 0)
                self.assertEqual(self.lib.multi_add(multi, easy), 0)
                attached.append(easy)
            self.assertGreaterEqual(self.lib.multi_fire_timer(multi), 0)
            deadline = time.monotonic() + 3
            while True:
                while True:
                    try:
                        conn, peer = listener.accept()
                    except BlockingIOError:
                        break
                    accepted.append(conn)
                    peers.add(peer)
                snapshot = self.lib.multi_socket_snapshot(multi)
                active_fds = transfer_fds(snapshot)
                if len(active_fds) == 3 and all(dict(snapshot)[fd] == 1 for fd in active_fds):
                    break
                if time.monotonic() >= deadline:
                    completed = []
                    while (message := self.lib.multi_drain(multi)) is not None:
                        completed.append(message[:2])
                    self.fail("connections never reached IN: snapshot=%r active=%r done=%r"
                              % (snapshot, self.lib.multi_active(multi), completed))
                for fd, ev in self.lib.poll_sockets(snapshot, 50):
                    self.assertGreaterEqual(self.lib.multi_socket_action(multi, fd, ev), 0)
                self.assertGreaterEqual(self.lib.multi_fire_timer(multi), 0)
            self.assertEqual(len(accepted), 3)
            local_ports = {self.lib.getinfo_long(easy, 0x200000 + 42) for easy in handles}
            self.assertEqual(local_ports, {peer[1] for peer in peers})
            for easy in list(attached):
                self.assertEqual(self.lib.multi_remove(multi, easy), 0)
                attached.remove(easy)
            remaining = dict(self.lib.multi_socket_snapshot(multi))
            self.assertTrue(active_fds.isdisjoint(remaining))

            self.assertEqual(native.nb_multi_socket_changes(multi, ffi.NULL, 0, total), 0)
            count = int(total[0])
            self.assertGreaterEqual(count, 9)
            small = ffi.new("nb_sock_info[]", count - 1)
            self.assertEqual(native.nb_multi_socket_changes(multi, small, count - 1, total), 0)
            self.assertEqual(int(total[0]), count)
            self.assertEqual(native.nb_multi_socket_changes(multi, ffi.NULL, 0, total), 0)
            self.assertEqual(int(total[0]), count)
            changes = self.lib.multi_socket_changes(multi)
            self.assertEqual(len(changes), count)
            state = {}
            for fd, action in changes:
                self.assertIn(action, (0, 1, 2, 3, 4))
                if action == 4:
                    self.assertIn(fd, state, "REMOVE without a registered socket")
                    state.pop(fd)
                else:
                    state[fd] = action
            self.assertEqual({fd: action for fd, action in state.items() if action}, remaining)
            self.assertTrue(active_fds.issubset({fd for fd, _ in changes}))
            for fd in active_fds:
                actions = [action for changed_fd, action in changes if changed_fd == fd]
                self.assertEqual(actions[0], 2)
                self.assertIn(1, actions[:-1])
                self.assertEqual(actions[-1], 4)
                self.assertEqual(actions.count(4), 1)
            self.assertEqual(self.lib.multi_socket_changes(multi), [])
            self.assertEqual(native.nb_multi_socket_changes(multi, ffi.NULL, 0, total), 0)
            self.assertEqual(int(total[0]), 0)
        finally:
            for easy in attached:
                self.lib.multi_remove(multi, easy)
            self.lib.multi_cleanup(multi)
            for easy in handles:
                self.lib.easy_cleanup(easy)
            for conn in accepted:
                conn.close()
            listener.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--package-path", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--backend", choices=("cffi", "ctypes"), default="cffi")
    args, remaining = parser.parse_known_args()
    os.environ["NB_CURL_BACKEND"] = args.backend
    sys.path.insert(0, str(Path(args.package_path).resolve()))
    unittest.main(argv=[sys.argv[0], *remaining], verbosity=2)
