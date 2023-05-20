import falcon, base64, secrets, gc, threading, wsgiref.simple_server, hashlib, getpass, socket, json, argparse, os, ctypes, sys
from typing import IO, Union

class Counter:
    def __init__(self, success_max: int = 0, failure_max: int = 0):
        self.success_count: int = 0
        self.failure_count: int = 0
        self.success_max = success_max
        self.failure_max = failure_max
    def success(self) -> None:
        self.success_count += 1
    def failure(self) -> None:
        self.failure_count += 1
    @property
    def ok(self) -> bool:
        return (self.success_max == 0 or self.success_count < self.success_max) and (self.failure_max == 0 or self.failure_count < self.failure_max)

class Shutdown:
    def __init__(self, server: wsgiref.simple_server.WSGIServer):
        self.server = server
        self.event = threading.Event()
        self.thread = threading.Thread(target=self._shutdown)
        self.thread.start()
    def _shutdown(self) -> None:
        self.event.wait()
        self.server.shutdown()
    def __call__(self) -> None:
        self.event.set()

def encrypt_secret(secret: bytes, symkey: bytes) -> bytes:
    if len(secret) >= len(symkey):
        raise RuntimeError('Secret has to be smaller than symmetric key')
    result = len(secret).to_bytes(1, 'big') + secret
    result = bytes([a^b for a, b in zip(result, symkey)])
    padding_size = len(symkey)-len(secret)-1
    result += symkey[-padding_size:]
    return result

class Resource:
    def __init__(self, identifier: bytes, secret: str, counter: Counter, shutdown: Shutdown):
        self.identifier  = identifier
        self.secret = secret
        self.counter = counter
        self.shutdown = shutdown
    def on_post(self, req, resp):
        data = req.stream.read(req.content_length or 0)
        if data == self.identifier:
            resp.content_type = falcon.MEDIA_TEXT
            resp.text = self.secret
            self.counter.success()
            if not self.counter.ok: self.shutdown()
            return
        resp.status = falcon.HTTP_404
        self.counter.failure()
        if not self.counter.ok: self.shutdown()

class Request_handler(wsgiref.simple_server.WSGIRequestHandler):
    logfile: IO
    def log_message(self, format, *args):
        Request_handler.logfile.write("%s - - [%s] %s\n" % (self.client_address[0], self.log_date_time_string(), format%args))
        Request_handler.logfile.flush()

def overwrite_memory_hack(obj: Union[str, bytes]):
    """This only works correctly for a string if it's purely ASCII."""
    size = len(obj)
    ptr = (ctypes.c_byte * size).from_address(id(obj) + sys.getsizeof(obj) - size - 1)
    mask = b'X'*size
    ctypes.memmove(ptr, mask, size)

def server():
    parser = argparse.ArgumentParser(description='Store a short secret in memory.', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--bind-address', default='0.0.0.0', help='Bind address')
    parser.add_argument('--port-min', type=int, default=13500, help='First port to try to bind to')
    parser.add_argument('--port-max', type=int, default=13599, help='Maximum port number to attempt')
    parser.add_argument('--client-file', default='~/.s5client.json', help='File for client process')
    parser.add_argument('--no-client-file', action='store_true', help='If set, no client file is produced, token shown on screen')
    parser.add_argument('--foreground', action='store_true', help='Do not go to background')
    parser.add_argument('--logfile', default='~/s5server.log', help='Log filename (use "stdout" to output to screen)')
    parser.add_argument('--success-max', type=int, default=1, help='Turn server off after that many successful attempts (0 for unlimited)')
    parser.add_argument('--failure-max', type=int, default=0, help='Turn server off after that many failed attempts (0 for unlimited)')
    args = parser.parse_args()

    token = secrets.token_bytes(96)
    identifier = token[:48]
    symkey = token[48:]

    secret_text = getpass.getpass('Enter secret: ')
    secret_bytes = secret_text.encode()
    response = base64.b64encode(encrypt_secret(secret_bytes, symkey)).decode()

    m = hashlib.new('sha256')
    m.update(secret_bytes)
    print("Secret's sha256: " + m.hexdigest()[:6] + '...')
    overwrite_memory_hack(secret_text)
    overwrite_memory_hack(secret_bytes)
    del secret_text, secret_bytes
    gc.collect()

    if not args.foreground:
        if (pid := os.fork()) > 0: exit(0)

    app = application = falcon.App()

    if args.logfile == 'stdout':
        Request_handler.logfile = sys.stdout
    else:
        Request_handler.logfile = open(os.path.expanduser(args.logfile), 'a')

    for port in range(args.port_min, args.port_max+2):
        if port > args.port_max: raise RuntimeError('Could not find a free port.')
        try:
            httpd = wsgiref.simple_server.make_server(args.bind_address, port, app, handler_class=Request_handler)
            break
        except OSError:
            pass
    hostname = socket.gethostname()
    print(f'Process {os.getpid()} listening on {hostname} on port {port}.')

    token = base64.b64encode(token).decode()
    client = {'host': hostname, 'bind_address': args.bind_address, 'port': port, 'token': token}
    if not args.no_client_file:
        with open(os.path.expanduser(args.client_file), 'w') as f:
            json.dump(client, f)
    else:
        print(f'Token: {token}')

    shutdown = Shutdown(httpd)
    counter = Counter(args.success_max, args.failure_max)
    app.add_route('/', Resource(identifier, response, counter, shutdown))
    httpd.serve_forever()
