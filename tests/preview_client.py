"""Browser-facing preview regressions. Real HTTP/Unix sockets; no SSH or production access."""
import concurrent.futures
import contextlib
from http.server import BaseHTTPRequestHandler
import http.client
import importlib.util
from pathlib import Path
import socketserver
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('preview', Path(__file__).parents[1] / 'src/preview/client.py')
preview = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preview)


class App(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_):
        pass

    def do_HEAD(self):
        if self.path == '/slow':
            time.sleep(3)
        self.send_response(405)
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_GET(self):
        if self.path == '/events':
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Connection', 'close')
            self.end_headers()
            for n in range(3):
                self.wfile.write(f'data: {n}\n\n'.encode()); self.wfile.flush(); time.sleep(.03)
        else:
            self.send_response(200)
            self.send_header('Content-Length', '2')
            self.end_headers(); self.wfile.write(b'ok')

    def do_POST(self):
        data = self.rfile.read(int(self.headers['Content-Length']))
        self.send_response(200)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers(); self.wfile.write(data)


class UnixServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True


class PreviewTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='cr-preview-', dir='/tmp')
        self.addCleanup(self.directory.cleanup)
        sock = Path(self.directory.name) / 'upstream.sock'
        self.upstream = UnixServer(str(sock), App)
        self.tunnel = SimpleNamespace(socket_path=sock, generation='test-generation', closed=False,
            process=SimpleNamespace(poll=lambda: None), connections=set(), connections_lock=threading.Lock())
        self.server = preview.Server(('127.0.0.1', 0), preview.Proxy)
        self.server.authority = f'p3000-test.localhost:{self.server.server_port}'
        self.server.tunnel = self.tunnel
        self.tunnel.server = self.server
        for server in [self.upstream, self.server]:
            threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .01}, daemon=True).start()
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)

    def request(self, method='GET', path='/', headers=None, body=None):
        with contextlib.closing(http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)) as connection:
            connection.request(method, path, body=body, headers={'Host': self.server.authority, **(headers or {})})
            response = connection.getresponse()
            return response.status, response.getheaders(), response.read()

    def test_browser_path_streaming_upload_and_readiness(self):
        self.assertTrue(preview.Tunnel.healthy(self.tunnel))  # HEAD 405 still proves transport works.
        self.assertEqual(self.request()[2], b'ok')
        self.assertEqual(self.request('GET', '/events')[2], b'data: 0\n\ndata: 1\n\ndata: 2\n\n')
        body = b'x' * 131072
        self.assertEqual(self.request('POST', '/', body=body)[2], body)
        self.assertIn(('Content-Security-Policy', "frame-ancestors 'self'"), self.request()[1])

    def test_host_origin_and_websocket_requests_are_private(self):
        for headers in [
            {'Host': 'attacker.example'}, {'Origin': 'https://attacker.example'},
            {'Upgrade': 'websocket'},
            {'Sec-Fetch-Site': 'cross-site', 'Sec-Fetch-Mode': 'navigate', 'Sec-Fetch-Dest': 'iframe'},
        ]:
            self.assertEqual(self.request(headers=headers)[0], 403)
        self.assertEqual(self.request(headers={'Sec-Fetch-Site': 'cross-site', 'Sec-Fetch-Mode': 'navigate', 'Sec-Fetch-Dest': 'document'})[0], 200)
        self.assertEqual(self.request('POST', '/', headers={'Transfer-Encoding': 'chunked'})[0], 411)

    def test_healthy_upstream_does_not_hide_broken_local_proxy(self):
        with contextlib.closing(preview.Upstream(self.tunnel.socket_path)) as connection:
            connection.request('HEAD', '/')
            self.assertEqual(connection.getresponse().status, 405)
        self.server.RequestHandlerClass = App
        self.assertFalse(preview.Tunnel.healthy(self.tunnel))

    def test_slow_http_does_not_block_other_browser_requests(self):
        with concurrent.futures.ThreadPoolExecutor() as pool:
            slow = pool.submit(self.request, 'HEAD', '/slow')
            started = time.monotonic()
            self.assertEqual(self.request()[2], b'ok')
            self.assertLess(time.monotonic() - started, 2)
            self.assertEqual(slow.result()[0], 405)


class MacJobTests(unittest.TestCase):
    def test_job_core_gave_up_on_never_runs(self):
        # Feedback #247: a slow Mac ran a --write job after Core told the agent "Mac unavailable", so a retry ran it twice.
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            preview.save(folder / 'config.json', {'macAccess': 'full'})
            posted = []
            def fetch(url, body, *_):
                posted.append(body['state'])
                raise preview.ControlError(404)  # Core already dropped the unconfirmed job.
            core = SimpleNamespace(url='http://core', headers={}, connection={}, fetch=fetch, key='core')
            preview.MacJobs(folder).execute(core, 'mac', {'id': 'job', 'command': f'touch {folder}/ran', 'write': True})
            self.assertFalse((folder / 'ran').exists())
            self.assertEqual(posted, ['running'])

    def test_ask_first_popup_shows_agent_text_as_text(self):
        # Security sweep: line breaks in a folder name could push the command out of view in the Ask first popup.
        shown = []
        class Popup:
            def __init__(self, args, **_):
                shown.append(args[3])
            def communicate(self):
                return 'Allow\n', None
        job = {'id': 'job', 'command': 'bash -s\necho two\N{RIGHT-TO-LEFT OVERRIDE}', 'cwd': '/tmp/a\nb' + 'c' * 300,
               'write': True, 'stdin': ''.join(f'echo {n}\r\n' for n in range(25)).encode().hex()}
        with mock.patch.object(preview.subprocess, 'Popen', Popup):
            self.assertTrue(preview.MacJobs(Path('/unused')).approve(SimpleNamespace(key='core'), job))
        lines = shown[0].split('\n')
        self.assertEqual(lines[2:12], ['Warning: 44 more characters of its input are not shown, and will also run.', '',
                                       'Command:', '    bash -s', '    echo two\\u202e', '',
                                       'Folder: /tmp/a\\nb' + 'c' * 191 + '…', '', 'Input (25 lines):', '    echo 0\\r'])
        self.assertEqual(lines[12:], [f'    echo {n}\\r' for n in range(1, 20)])
        self.assertTrue(all(c.isprintable() or c == '\n' for c in shown[0]))
        # Escapes count against the limit, and the hidden count stays in the agent's own characters.
        self.assertEqual(preview.visible('\0' * 300, 600, 10), ('\\x00' * 150, 150))


if __name__ == '__main__':
    unittest.main()
