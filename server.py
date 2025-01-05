from typing import Union
from fastapi import FastAPI, Cookie, Body, WebSocket
from fastapi.responses import PlainTextResponse, JSONResponse
import asyncio
import json

import uvicorn

from .crypto import Crypto_AES, Crypto_RSA
from .common import Config, find_packet

import uuid
import queue, socket
import threading

settings = Config()

app = FastAPI(
    title='HTTP Server',
    openapi_url=None,
    docs_url=None,
    redoc_url=None
)
sessions = {}
rsa = Crypto_RSA()


class Forwarder(object):
    def __init__(self, host: str, port: int) -> None:
        self.cipher: Crypto_AES = None
        self.get_nonce = 0.0
        self.put_nonce = 0.0
        self.ws_nonce = 0.0
        self.host = host
        self.port = port
        self.sock = None
        self.tokenid = 0
        self.res_tokenid = 0
        self.input_thread = None
        self.output_thread = None
        self.iqueue = queue.Queue()
        self.oqueue = queue.Queue(settings.queue_size)
        self.reorder_buffer = []
        self.watchdog_timer = threading.Event()
        self.watchdog_thread = None

    def open(self):
        try:
            self.sock = socket.create_connection((self.host, self.port))
        except Exception as identifier:
            print('[D] Failed to connect:', self.host, self.port, identifier)
            return
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)

    def close(self):
        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            self.sock.close()
            self.sock = None
            self.iqueue.put(None)
            self.watchdog_timer.set()

        while not self.oqueue.empty():
            try:
                self.oqueue.get_nowait()
            except Exception:
                break

        self.input_thread.join()
        self.output_thread.join()

    def handle_input(self):
        while self.sock:
            _found = False
            if len(self.reorder_buffer) == 0:
                _item = self.iqueue.get()
                if _item is None:
                    break
                if _item[0] <= self.tokenid:
                    print('[W] Received a duplicated packet, ignored.')
                    continue
                if _item[0] != self.tokenid + 1:
                    print('[W] Tokenid mismatch:', _item[0], 'expected:', self.tokenid + 1)
                    self.iqueue.put(_item)
                else:
                    _found = True
            else:
                for index in range(len(self.reorder_buffer)):
                    if self.reorder_buffer[index][0] == self.tokenid + 1:
                        _item = self.reorder_buffer.pop(index)
                        _found = True
                        break
            if not _found:
                try:
                    _item = find_packet(self.tokenid + 1, self.iqueue, self.reorder_buffer, settings.reorder_limit)
                except queue.Empty:
                    print('[E] Packet loss: Timed out')
                    break
                except Exception as identifier:
                    if str(identifier) != 'Abort':
                        print('[E] Packet loss:', identifier)
                    break

            self.tokenid = _item[0]
            try:
                self.sock.sendall(_item[1])
            except Exception:
                break
            if len(_item[1]) == 0:
                break
        if self.sock:
            try:
                self.sock.sendall(b'')
                self.sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
        if self.sock:
            self.sock.close()
            self.sock = None
        self.watchdog_timer.set()
        print('[D] Input closed.')

    def handle_output(self):
        while self.sock:
            try:
                _d = self.sock.recv(settings.buffer_size)
                # print('[D] recv:', _d)
            except Exception:
                self.oqueue.put(b'')
                break
            self.oqueue.put(_d)
            if len(_d) == 0:
                break
        self.iqueue.put(None)
        print('[D] Output closed.')

    def watchdog(self):
        while self.sock:
            if self.watchdog_timer.wait(30.0):
                self.watchdog_timer.clear()
            else:
                print('[E] Session timed out.')
                self.close()


def clean_up():
    for _sid in list(sessions.keys()):
        _session: Forwarder = sessions[_sid]
        if not _session.sock:
            _session.watchdog_thread.join()
            sessions.pop(_sid, None)
            print('[I] Deleted dead session:', _sid)


@app.get('/')
def root():
    return PlainTextResponse(rsa.public_pem, headers={'Connection': 'keep-alive'})


@app.get('/api/login')
def login(
    secret: str,
    token: str
):
    try:
        _pass = rsa.decrypt(secret)
    except Exception as identifier:
        print('[E] Failed to decrypt secret:', identifier)
        return JSONResponse(
            {'Error': 'Invalid secret'},
            status_code=400,
            headers={'Connection': 'close'}
        )

    _aes = Crypto_AES(_pass)
    try:
        _forward_srv = _aes.decrypt(token)
    except Exception as identifier:
        print('[E] Failed to decrypt token:', identifier)
        return JSONResponse(
            {'Error': 'Invalid token'},
            status_code=400,
            headers={'Connection': 'close'}
        )

    try:
        _forward_srv = _forward_srv.decode().split(':')
        _host = _forward_srv[0]
        _port = int(_forward_srv[1])
    except Exception as identifier:
        print('[D] Invalid host/port in token:', identifier)
        return JSONResponse(
            {'Error': 'Invalid token'},
            status_code=400,
            headers={'Connection': 'close'}
        )

    clean_up()
    if len(sessions) >= settings.max_sessions:
        return JSONResponse(
            {'Error': 'Too many sessions'},
            status_code=429,
            headers={'Connection': 'close'}
        )

    _id = str(uuid.uuid4())
    while _id in sessions:
        _id = str(uuid.uuid4())

    _session = Forwarder(_host, _port)
    _session.open()
    if _session.sock:
        print('[I] Session opened:', _id, _host, _port)
        _session.cipher = _aes
        _session.input_thread = threading.Thread(target=_session.handle_input)
        _session.input_thread.start()
        _session.output_thread = threading.Thread(target=_session.handle_output)
        _session.output_thread.start()
        _session.watchdog_thread = threading.Thread(target=_session.watchdog)
        _session.watchdog_thread.start()
        sessions[_id] = _session

        _res = JSONResponse(
            {'Error': None, 'sid': _id},
            headers={'Connection': 'keep-alive'}
        )
        _res.set_cookie(key='sid', value=_id, path='/api/')
        return _res
    else:
        return JSONResponse(
            {'Error': 'Failed to connect to server'},
            status_code=503,
            headers={'Connection': 'close'}
        )


def put_iqueue(session: Forwarder, tokenid, token):
    try:
        tokenid = session.cipher.decrypt(tokenid)
    except Exception as identifier:
        print('[E] Failed to decrypt tokenid:', identifier)
        return JSONResponse(
            {'Error': 'Invalid tokenid'},
            status_code=400,
            headers={'Connection': 'close'}
        )

    # print('[D] received tokenid:', tokenid)
    for _id, _encrypted_token in zip(tokenid.decode().split(' '), token.split(' ')):
        try:
            _id = int(_id)
        except Exception as identifier:
            print('[E] Invalid tokenid in request:', identifier)
            return JSONResponse(
                {'Error': 'Invalid token id'},
                status_code=400,
                headers={'Connection': 'close'}
            )
        try:
            _token = session.cipher.decrypt(_encrypted_token)
        except Exception as identifier:
            print('[E] Failed to decrypt token:', identifier)
            return JSONResponse(
                {'Error': 'Invalid token'},
                status_code=400,
                headers={'Connection': 'close'}
            )
        if not session.sock:
            break
        session.iqueue.put((int(_id), _token))
        if len(_token) == 0:
            break


def get_oqueue(session: Forwarder, sid, timeout):
    try:
        _outq_item = session.oqueue.get(timeout=timeout)
    except Exception:
        if not session.sock:
            session.res_tokenid += 1
            _res = JSONResponse(
                {
                    'Error': 'Timeout',
                    'tokenid': session.cipher.encrypt(str(session.res_tokenid).encode()),
                    'token': session.cipher.encrypt(b''),
                    'sid': sid
                },
                headers={'Connection': 'keep-alive'}
            )
            _res.set_cookie(key='sid', value=sid, path='/api/')
            return _res
        _res = JSONResponse(
            {'Error': 'Timeout', 'sid': sid},
            status_code=202,
            headers={'Connection': 'keep-alive'}
        )
        _res.set_cookie(key='sid', value=sid, path='/api/')
        return _res

    session.res_tokenid += 1
    _res_tokenid = [str(session.res_tokenid)]
    _res_token = [session.cipher.encrypt(_outq_item)]

    while not session.oqueue.empty():
        try:
            _outq_item = session.oqueue.get_nowait()
        except Exception:
            break
        session.res_tokenid += 1
        _res_tokenid.append(str(session.res_tokenid))
        _res_token.append(session.cipher.encrypt(_outq_item))
        if len(_res_tokenid) >= settings.queue_size:
            break

    # print('[D] sending tokenid:', sid, _res_tokenid)
    _res = JSONResponse(
        {
            'Error': None,
            'tokenid': session.cipher.encrypt(' '.join(_res_tokenid).encode()),
            'token': ' '.join(_res_token),
            'sid': sid
        },
        headers={'Connection': 'keep-alive'}
    )
    _res.set_cookie(key='sid', value=sid, path='/api/')
    # _res.set_cookie(key='tokenid', value=session.cipher.encrypt(' '.join(_res_tokenid)), path='/api/')
    # _res.set_cookie(key='token', value=' '.join(_res_token), path='/api/')
    return _res


@app.get('/api/session')
def session(
    sid: str,
    nonce: str,
    tokenid: Union[str, None],
    token: Union[str, None]
):
    if sid not in sessions:
        return JSONResponse(
            {'Error': 'Session ID not found'},
            status_code=404,
            headers={'Connection': 'close'}
        )
    if type(tokenid) is not type(token):
        return JSONResponse(
            {'Error': 'Invalid token'},
            status_code=400,
            headers={'Connection': 'close'}
        )

    _session: Forwarder = sessions[sid]
    try:
        _nonce = float(_session.cipher.decrypt(nonce))
    except Exception as identifier:
        print('[E] Failed to decrypt nonce:', identifier)
        return JSONResponse(
            {'Error': 'Invalid nonce'},
            status_code=400,
            headers={'Connection': 'close'}
        )

    if not _session.sock:
        clean_up()
        return JSONResponse(
            {'Error': 'Session already closed'},
            status_code=409,
            headers={'Connection': 'close'}
        )

    _timeout = 10.0
    if tokenid is not None:
        if _nonce <= _session.put_nonce:
            print('[E] Received duplicated nonce.')
            return JSONResponse(
                {'Error': 'Duplicated nonce'},
                status_code=403,
                headers={'Connection': 'close'}
            )
        else:
            _session.put_nonce = _nonce

        _timeout = 0.05

        _res = put_iqueue(_session, tokenid, token)
        if _res is not None:
            return _res

    else:
        if _nonce <= _session.get_nonce:
            print('[E] Received duplicated nonce.')
            return JSONResponse(
                {'Error': 'Duplicated nonce'},
                status_code=403,
                headers={'Connection': 'close'}
            )
        else:
            _session.get_nonce = _nonce

    _res = get_oqueue(_session, sid, _timeout)
    _session.watchdog_timer.set()
    return _res


@app.post('/api/session')
@app.put('/api/session')
@app.delete('/api/session')
@app.patch('/api/session')
# content-type: application/json required
def session_with_body(
    sid: str,
    nonce: str,
    tokenid: str,
    token: str
):
    if sid not in sessions:
        return JSONResponse(
            {'Error': 'Session ID not found'},
            status_code=404,
            headers={'Connection': 'close'}
        )

    _session: Forwarder = sessions[sid]
    try:
        _nonce = float(_session.cipher.decrypt(nonce))
    except Exception as identifier:
        print('[E] Failed to decrypt nonce:', identifier)
        return JSONResponse(
            {'Error': 'Invalid nonce'},
            status_code=400,
            headers={'Connection': 'close'}
        )

    if not _session.sock:
        clean_up()
        return JSONResponse(
            {'Error': 'Session already closed'},
            status_code=409,
            headers={'Connection': 'close'}
        )

    if _nonce <= _session.put_nonce:
        print('[E] Received duplicated nonce.')
        return JSONResponse(
            {'Error': 'Duplicated nonce'},
            status_code=403,
            headers={'Connection': 'close'}
        )
    else:
        _session.put_nonce = _nonce

    _res = put_iqueue(_session, tokenid, token)
    if _res is not None:
        return _res

    _res = get_oqueue(_session, sid, 0.02)
    _session.watchdog_timer.set()
    return _res


async def recv_ws(session: Forwarder, websocket: WebSocket):
    print('[D] Websocket recv started.')
    try:
        while session.sock:
            _json = await websocket.receive_bytes()
            try:
                _json = json.loads(_json)
            except Exception as identifier:
                print('[E] Failed to parse JSON:', identifier)
                await websocket.send_json({'Error': 'Invalid JSON'})
                break
            # print('[D] Websocket recv:', _json)

            _tokenid = _json.get('tokenid', None)
            _token = _json.get('token', None)

            if type(_tokenid) is not type(_token):
                await websocket.send_json({'Error': 'Invalid token'})
                break

            if _tokenid is not None:
                _res = put_iqueue(session, _tokenid, _token)
                if _res is not None:
                    await websocket.send_bytes(_res.body)
                    break
            session.watchdog_timer.set()
        print('[D] Websocket recv closed.')
    except Exception as identifier:
        print('[D] Websocket recv disconnected:', identifier)
    try:
        await websocket.close()
    except Exception:
        pass


async def send_ws(session: Forwarder, sid, websocket: WebSocket):
    print('[D] Websocket send started.')
    try:
        while session.sock:
            _res = await asyncio.to_thread(get_oqueue, session, sid, 10.0)
            _res_obj = json.loads(_res.body)
            if _res_obj.get('Error', ...) is None:
                session.watchdog_timer.set()
            await websocket.send_bytes(_res.body)
            # print('[D] Websocket sent:', _res.body)
        print('[D] Websocket send closed.')
    except Exception as identifier:
        print('[D] Websocket send disconnected:', identifier)
    try:
        await websocket.close()
    except Exception:
        pass


@app.websocket('/api/session')
async def session_websocket(
    websocket: WebSocket,
    sid: str = Cookie(default=...),
    nonce: str = Cookie(default=...)
):
    if sid not in sessions:
        return JSONResponse(
            {'Error': 'Session ID not found'},
            status_code=404,
            headers={'Connection': 'close'}
        )

    _session: Forwarder = sessions[sid]
    try:
        _nonce = float(_session.cipher.decrypt(nonce))
    except Exception as identifier:
        print('[E] Failed to decrypt nonce:', identifier)
        return JSONResponse(
            {'Error': 'Invalid nonce'},
            status_code=400,
            headers={'Connection': 'close'}
        )

    if not _session.sock:
        clean_up()
        return JSONResponse(
            {'Error': 'Session already closed'},
            status_code=409,
            headers={'Connection': 'close'}
        )

    if _nonce <= _session.ws_nonce:
        print('[E] Received duplicated nonce.')
        return JSONResponse(
            {'Error': 'Duplicated nonce'},
            status_code=403,
            headers={'Connection': 'close'}
        )
    else:
        _session.ws_nonce = _nonce

    await websocket.accept(headers=[(b'Set-Cookie', f'sid={sid}; Path=/api/'.encode())])

    await asyncio.gather(
        recv_ws(_session, websocket),
        send_ws(_session, sid, websocket)
    )


@app.get('/api/logout')
def logout(
    sid: str,
    nonce: str
):
    print('[I] Closing session:', sid)
    if sid not in sessions:
        return JSONResponse(
            {'Error': 'Session ID not found'},
            status_code=404,
            headers={'Connection': 'close'}
        )

    _session: Forwarder = sessions[sid]
    try:
        _nonce = float(_session.cipher.decrypt(nonce))
    except Exception as identifier:
        print('[E] Failed to decrypt nonce:', identifier)
        return JSONResponse(
            {'Error': 'Invalid nonce'},
            status_code=400,
            headers={'Connection': 'close'}
        )
    if _nonce <= _session.put_nonce or _nonce <= _session.get_nonce:
        print('[E] Received duplicated nonce.')
        return JSONResponse(
            {'Error': 'Duplicated nonce'},
            status_code=403,
            headers={'Connection': 'close'}
        )

    _session.close()
    _session.watchdog_thread.join()
    sessions.pop(sid, None)
    clean_up()
    return JSONResponse({'Error': None}, headers={'Connection': 'close'})


def server(
    host,
    port,
    max_sessions=None,
    cert=None,
    key=None,
    buffer_size=None,
    queue_size=None,
    reorder_limit=None
):
    if max_sessions is not None:
        settings.max_sessions = max_sessions
    if buffer_size is not None:
        settings.buffer_size = buffer_size
    if queue_size is not None:
        settings.queue_size = queue_size
    if reorder_limit is not None:
        settings.reorder_limit = reorder_limit

    rsa.generate()
    print('[I] Starting server mode.')
    print('[I] Listening on:', f'{host if host else "<any>"}:{port}')
    print('[I] Public key:')
    print(rsa.public_pem)
    try:
        uvicorn.run(
            app=app,
            host=host,
            port=port,
            http='h11',
            ws='websockets',
            timeout_keep_alive=30,
            log_level='warning',
            ssl_certfile=cert,
            ssl_keyfile=key,
            h11_max_incomplete_event_size=1048576  # big enough to handle large cookies
        )
    except Exception as identifier:
        print('[E] Server start failed:', identifier)
