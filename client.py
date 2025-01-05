import socket, threading, multiprocessing

from requests import Request, Session
from urllib.request import getproxies
from urllib.parse import urlparse, unquote
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

import json
import queue

import sys, os, time
from uuid import uuid4
from .crypto import Crypto_AES, Crypto_RSA
from .common import Config, find_packet

settings = Config()


def base_headers():
    return {
        'Host': settings.forward_hosth,
        'Cache-Control': 'no-cache',
        'Pragma': 'no-cache',
        'Connection': 'keep-alive',
        'Proxy-Connection': 'keep-alive'
    }


def get_ips(host):
    try:
        _ips = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM, flags=socket.AI_ALL)
    except Exception:
        return ([], [])
    _ipv4s = [sockaddr[0] for family, *_, sockaddr in _ips if family == socket.AF_INET]
    _ipv6s = [sockaddr[0] for family, *_, sockaddr in _ips if family == socket.AF_INET6]
    return (_ipv4s, _ipv6s)


def handle_connection(
    conn: socket.socket,
    addr,
    forward_url: str = None,
    resolve=False,
    ipv6=False,
    method=None,
    forward_srv=None,
    no_verify=False,
    buffer_size=None,
    queue_size=None,
    reorder_limit=None
):
    import urllib3
    if no_verify:
        urllib3.disable_warnings()

    if forward_url is not None:
        _url = urlparse(forward_url)
        settings.forward_hosth = _url.hostname
        settings.forward_hostn = _url.hostname
        settings.forward_port = _url.port or (443 if _url.scheme == 'https' else 80)

        if resolve:
            _f_ipv4s, _f_ipv6s = get_ips(_url.hostname)
            try:
                if ipv6:
                    _f_ipv6 = _f_ipv6s[0]
                    settings.forward_url = forward_url.replace(
                        f'://{_url.netloc}',
                        f'://[{_f_ipv6}]:{settings.forward_port}',
                        1
                    )
                    settings.forward_hostn = _f_ipv6
                else:
                    _f_ipv4 = _f_ipv4s[0]
                    settings.forward_url = forward_url.replace(
                        f'://{_url.netloc}',
                        f'://{_f_ipv4}:{settings.forward_port}',
                        1
                    )
                    settings.forward_hostn = _f_ipv4
            except Exception:
                print('[W] Resolve FQDN failed, sending requests with FQDN directly.')
                settings.forward_url = forward_url
        else:
            settings.forward_url = forward_url

    if method is not None:
        settings.method = method
    if forward_srv is not None:
        settings.forward_srv = forward_srv
    if buffer_size is not None:
        settings.buffer_size = buffer_size
    if queue_size is not None:
        settings.queue_size = queue_size
    if reorder_limit is not None:
        settings.reorder_limit = reorder_limit

    def close():
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        conn.close()
        print('[I] Connection closed:', addr)

    proxies = {
        _url.scheme: settings.forward_url,
    }

    _client = Session()
    # Set up retries for handling failed requests
    retries = Retry(
        total=5,                # Number of retry attempts
        backoff_factor=0.3,     # Delay between retries (e.g., exponential backoff)
        status_forcelist=[500, 502, 503, 504],  # Retry for these HTTP statuses
    )

    # Configure the HTTP adapter with connection pooling
    adapter = HTTPAdapter(
        pool_connections=10,    # Maximum number of connections to keep in the pool
        pool_maxsize=50,        # Maximum number of connections allowed in the pool
        max_retries=retries     # Retry configuration
    )
    _client.mount(f"{_url.scheme}://", adapter)
    _client.proxies.update(proxies)

    if no_verify:
        _client.verify = False
    try:
        _res = _client.get(
            f'{settings.forward_url}/?a={uuid4()}',
            headers=base_headers(),
            timeout=10.0
        )
    except (KeyboardInterrupt, SystemExit):
        close()
        return
    except Exception as identifier:
        print('[E] Request / failed:', identifier)
        close()
        return
    if _res.status_code >= 400:
        print('[E] Response / invalid:', _res.status_code, _res.text)
        close()
        return

    _pem = _res.text
    _rsa = Crypto_RSA()
    try:
        _rsa.load_public_key(_pem)
    except Exception as identifier:
        print('[E] Invalid public key:', identifier)
        print(_pem)
        close()
        return

    _cookie = {}
    # with OAEP padding: maxLen(190)=keyLen(2048)/8 - 2*hashLen(256)/8 - 2
    _pass = os.urandom(190)
    _cookie['secret'] = _rsa.encrypt(_pass)
    _aes = Crypto_AES(_pass)
    _cookie['token'] = _aes.encrypt(settings.forward_srv.encode())
    _req = Request(
        method='GET',
        url=f'{settings.forward_url}/api/login',
        headers=base_headers(),
        params=_cookie
    )
    try:
        _res = _client.send(_req.prepare(), timeout=10.0)
    except (KeyboardInterrupt, SystemExit):
        close()
        return
    except Exception as identifier:
        print('[E] Request to login failed:', identifier.args)
        close()
        return
    if _res.status_code >= 400:
        print('[E] Response from login invalid:', _res.status_code, _res.text)
        close()
        return
    _sid = _res.json().get('sid')
    if _sid is None:
        print('[E] Invalid sid in response from login.')
        close()
        return
    print('[I] Session started:', _sid)
    _cookie['sid'] = _sid
    _cookie.pop('secret')
    _cookie.pop('token')

    _export_queue = queue.Queue(settings.queue_size)
    _import_queue = queue.Queue()

    _input_thread = threading.Thread(target=handle_input, args=(conn, _import_queue, _export_queue))
    _input_thread.start()
    _output_thread = threading.Thread(target=handle_output, args=(conn, _import_queue))
    _output_thread.start()

    _done = threading.Event()

    if settings.method == 'WS':
        handle_ws(
            equeue=_export_queue,
            iqueue=_import_queue,
            sid=_sid,
            aes=_aes,
            done=_done,
            no_verify=no_verify
        )
    else:
        _transfer_put = threading.Thread(
            target=handle_transfer,
            args=(_export_queue, _import_queue, _client, _sid, _aes, 'put', _done)
        )
        _transfer_put.start()
        _transfer_get = threading.Thread(
            target=handle_transfer,
            args=(_export_queue, _import_queue, _client, _sid, _aes, 'get', _done)
        )
        _transfer_get.start()

        try:
            _transfer_put.join()
            _transfer_get.join()
        except (KeyboardInterrupt, SystemExit):
            _import_queue.put(None)

    while not _export_queue.empty():
        try:
            _export_queue.get_nowait()
        except Exception:
            break
    _input_thread.join()
    _output_thread.join()
    close()

    # logout
    _cookie['nonce'] = _aes.encrypt(str(time.time()).encode())
    _req = Request(
        method='GET',
        url=f'{settings.forward_url}/api/logout',
        headers={
            'Host': settings.forward_hosth,
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'Connection': 'close',
            'Proxy-Connection': 'close'
        },
        params=_cookie
    )
    try:
        _client.send(_req.prepare(), timeout=10.0)
        _client.close()
    except (KeyboardInterrupt, SystemExit):
        return
    except Exception:
        return
    finally:
        print('[I] Session ended:', _sid)


def handle_input(conn: socket.socket, iqueue: queue.Queue, equeue: queue.Queue):
    while True:
        try:
            _d = conn.recv(settings.buffer_size)
        except Exception:
            equeue.put(b'')
            break
        # print('[D] Input:', _d)
        equeue.put(_d)
        if len(_d) == 0:
            break
    try:
        equeue.put_nowait(None)
    except Exception:
        pass
    iqueue.put(None)
    print('[D] Input closed.')


def handle_output(conn: socket.socket, iqueue: queue.Queue):
    _res_tokenid = 0
    _reorder_buffer = []

    while True:
        _found = False
        if len(_reorder_buffer) == 0:
            _item = iqueue.get()
            if _item is None:
                break
            if _item[0] <= _res_tokenid:
                print('[W] Received a duplicated packet, ignored.')
                continue
            if _item[0] != _res_tokenid + 1:
                print('[W] Response tokenid mismatch:', _item[0], 'expected:', _res_tokenid + 1)
                _reorder_buffer.append(_item)
            else:
                _found = True
        else:
            for index in range(len(_reorder_buffer)):
                if _reorder_buffer[index][0] == _res_tokenid + 1:
                    _item = _reorder_buffer.pop(index)
                    _found = True
                    break
        if not _found:
            try:
                _item = find_packet(_res_tokenid + 1, iqueue, _reorder_buffer, settings.reorder_limit)
            except queue.Empty:
                print('[E] Response packet loss: Timed out')
                break
            except Exception as identifier:
                if str(identifier) != 'Abort':
                    print('[E] Response packet loss:', identifier)
                break

        _res_tokenid = _item[0]
        try:
            # print('[D] Output:', _item)
            conn.sendall(_item[1])
        except Exception:
            break
        if len(_item[1]) == 0:
            break
    try:
        conn.sendall(b'')
    except Exception:
        pass
    try:
        conn.shutdown(socket.SHUT_RDWR)
    except Exception:
        pass
    conn.close()
    print('[D] Output closed.')


tokenid = 0


def get_equeue(equeue: queue.Queue, aes: Crypto_AES, done: threading.Event):
    _token = [equeue.get()]
    _id = []

    while not equeue.empty():
        try:
            _token.append(equeue.get_nowait())
        except Exception:
            break
        if len(_token) >= settings.queue_size:
            break

    global tokenid
    for _item in _token:
        if _item is None:
            done.set()
            break
        if len(_item) == 0:
            done.set()
        tokenid += 1
        _id.append(str(tokenid))

    if len(_id) == 0:
        return  # got only None

    for _index in range(len(_id)):
        _token[_index] = aes.encrypt(_token[_index])

    # print('[D] sending tokenid:', sid, _id)
    _req_tokenid = aes.encrypt(' '.join(_id).encode())
    _req_token = ' '.join(_token[:len(_id)])
    return (_req_tokenid, _req_token)


def put_iqueue(iqueue: queue.Queue, data: dict[str, str], aes: Crypto_AES, done: threading.Event):
    def terminate():
        done.set()
        iqueue.put(None)

    _res_tokenid = data.get('tokenid', None)
    _res_token = data.get('token', None)
    if _res_tokenid is None or _res_token is None:
        return
    try:
        _res_tokenid = aes.decrypt(_res_tokenid)
    except Exception as identifier:
        print('[E] Invalid tokenid in response from session:', identifier)
        terminate()
        return
    for _id, _encrypted in zip(_res_tokenid.decode().split(' '), _res_token.split(' ')):
        try:
            _id = int(_id)
        except Exception as identifier:
            print('[E] Invalid tokenid in response from session:', identifier)
            terminate()
            return
        try:
            _d = aes.decrypt(_encrypted)
        except Exception as identifier:
            print('[E] Failed to decrypt token from response from session:', identifier)
            terminate()
            return
        iqueue.put((_id, _d))
        if len(_d) == 0:
            done.set()
            break


from websockets.sync.client import ClientConnection


def _ws_send(
    equeue: queue.Queue,
    client: ClientConnection,
    aes: Crypto_AES,
    done: threading.Event
):
    print('[D] Websocket send thread started.')
    _body = {}
    while not done.is_set():
        _req_data = get_equeue(equeue, aes, done)
        if _req_data is None:
            break
        _body['tokenid'], _body['token'] = _req_data
        try:
            client.send(json.dumps(_body).encode())
        except Exception as identifier:
            print('[D] Send websocket failed:', identifier)
            done.set()
            break
        # print('[D] Sent websocket:', _body)
    client.close()
    print('[D] Websocket send thread closed.')


def _ws_recv(
    iqueue: queue.Queue,
    client: ClientConnection,
    aes: Crypto_AES,
    done: threading.Event
):
    def terminate():
        done.set()
        iqueue.put(None)

    print('[D] Websocket receive thread started.')
    while not done.is_set():
        try:
            _res = client.recv(timeout=20.0)
            # print('[D] Received websocket:', _res)
        except Exception as identifier:
            print('[D] Receive websocket failed:', identifier)
            terminate()
            break

        if len(_res) == 0:
            terminate()
            break

        try:
            _res_data = json.loads(_res)
        except Exception as identifier:
            print('[E] Failed to parse response from session:', identifier)
            terminate()
            break
        if _res_data.get('Error', None) == 'Timeout':
            try:
                client.send(b'{}')
            except Exception:
                pass
        put_iqueue(iqueue, _res_data, aes, done)
    else:
        iqueue.put(None)
    client.close()
    print('[D] Websocket receive thread closed.')


def handle_ws(
    equeue: queue.Queue,
    iqueue: queue.Queue,
    sid: str,
    aes: Crypto_AES,
    done: threading.Event,
    no_verify=False
):
    import socks
    from websockets.sync.client import connect
    import ssl

    print('[D] Websocket mode started.')
    _cookie = {}
    _cookie['sid'] = sid
    _cookie['nonce'] = aes.encrypt(str(time.time()).encode())
    _cookie_text = ''
    for key in _cookie.keys():
        _cookie_text += f'{key}={_cookie[key]}; '
    _cookie_text = _cookie_text.strip().strip(';')

    _http_proxy = getproxies().get('http', '')
    _https_proxy = getproxies().get('https', _http_proxy)
    if settings.forward_url.startswith('https'):
        _proxy = urlparse(_https_proxy)
    else:
        _proxy = urlparse(_http_proxy)
    if _proxy.hostname:
        if _proxy.scheme.startswith('socks5'):
            _p_type = socks.SOCKS5
            _p_port = 1080
        elif _proxy.scheme.startswith('socks4'):
            _p_type = socks.SOCKS4
            _p_port = 1080
        elif _proxy.scheme == 'http':
            _p_type = socks.HTTP
            _p_port = 80
        else:
            print('[E] Proxy scheme not supported:', _proxy.scheme)
            iqueue.put(None)
            return
        if _proxy.port:
            _p_port = _proxy.port
        print('[D] Using proxy:', f'{_proxy.scheme}://{_proxy.hostname}:{_p_port}')

        try:
            _sock = socket.socket(socket.AF_INET6)
            _sock.connect((_proxy.hostname, _p_port))
            _sock.shutdown(socket.SHUT_RDWR)
            _sock.close()
            _sock = socks.socksocket(socket.AF_INET6)
        except Exception:
            _sock = socks.socksocket(socket.AF_INET)
        finally:
            _p_user = _proxy.username
            if _p_user is not None:
                _p_user = unquote(_p_user)
            _p_pass = _proxy.password
            if _p_pass is not None:
                _p_pass = unquote(_p_pass)
            _sock.set_proxy(
                _p_type,
                _proxy.hostname,
                _p_port,
                username=_p_user,
                password=_p_pass
            )
        try:
            _sock.connect((settings.forward_hostn, settings.forward_port))
        except Exception as identifier:
            print('[E] Failed to connect to proxy:', identifier)
            iqueue.put(None)
            return
        print('[D] Proxy connected.')
    else:
        print('[D] No proxy used.')
        try:
            _sock = socket.socket(socket.AF_INET6)
            _sock.connect((settings.forward_hostn, settings.forward_port))
        except Exception:
            try:
                _sock = socket.socket(socket.AF_INET)
                _sock.connect((settings.forward_hostn, settings.forward_port))
            except Exception as identifier:
                print('[E] Failed to connect WebSocket to server:', identifier)
                iqueue.put(None)
                return

    if settings.forward_url.startswith('https'):
        _ssl_context = ssl.create_default_context()
        if no_verify:
            _ssl_context.check_hostname = False
            _ssl_context.verify_mode = ssl.CERT_NONE
    else:
        _ssl_context = None

    try:
        _client = connect(
            f'{settings.forward_url.replace('http', 'ws', 1).replace(
                f'://{settings.forward_hostn}',
                f'://{settings.forward_hosth}',
                1
            )}/api/session',
            sock=_sock,
            ssl_context=_ssl_context,
            additional_headers={'Cookie': _cookie_text},
            compression=None,
            close_timeout=1.0
        )
    except Exception as identifier:
        print('[E] Connect websocket to session failed:', identifier)
        iqueue.put(None)
        return
    if not _client.response.headers.get('Set-Cookie', '').startswith(f'sid={sid};'):
        print('[E] Invalid sid in response from session.')
        iqueue.put(None)
        return

    _send_thread = threading.Thread(target=_ws_send, args=(equeue, _client, aes, done))
    _send_thread.start()
    _recv_thread = threading.Thread(target=_ws_recv, args=(iqueue, _client, aes, done))
    _recv_thread.start()
    _send_thread.join()
    _recv_thread.join()
    print('[D] Websocket mode closed.')


def _transfer(
    iqueue: queue.Queue,
    client: Session,
    method,
    cookies: dict[str, str],
    body: dict[str, str],
    aes: Crypto_AES,
    done: threading.Event
):
    def terminate():
        done.set()
        iqueue.put(None)

    _req = Request(
        method=method,
        url=f'{settings.forward_url}/api/session?a={uuid4()}',
        headers=base_headers(),
        params=cookies + body,
        # content-type: application/json is auto provided
    )

    if cookies.get('tokenid', None) or body.get('tokenid', None):
        _timeout = 10.0
    else:
        _timeout = 20.0

    try:
        _res = client.send(_req.prepare(), timeout=_timeout)
    except Exception as identifier:
        print('[E] Request to session failed:', identifier.args)
        terminate()
        return
    if _res.status_code >= 500:
        _fixed = False
        for _ in range(5):
            print('[W] Response from session invalid:', _res.status_code, 'retring...')
            time.sleep(0.5)
            try:
                _res = client.send(_req.prepare(), timeout=_timeout)
            except Exception as identifier:
                print('[E] Request to session failed:', identifier.args)
                terminate()
                return
            if _res.status_code < 500:
                _fixed = True
                break
        if not _fixed:
            print('[E] Response from session invalid:', _res.status_code, _res.text)
            for key in _res.headers.keys():
                print(f'{key}: {_res.headers[key]}')
            terminate()
            return
    if _res.status_code >= 400:
        print('[E] Response from session invalid:', _res.status_code, _res.text)
        terminate()
        return
    if _res.cookies.get('sid', None) != cookies.get('sid', None):
        print('[E] Invalid sid in response from session.')
        terminate()
        return

    try:
        _res_data = _res.json()
    except Exception as identifier:
        print('[E] Failed to parse response from session:', identifier)
        terminate()
        return
    put_iqueue(iqueue, _res_data, aes, done)


def handle_transfer(
    equeue: queue.Queue,
    iqueue: queue.Queue,
    client: Session,
    sid: str,
    aes: Crypto_AES,
    mode: str,
    done: threading.Event
):
    print('[D] Transfer started, mode:', mode)
    _cookie = {}
    _cookie['sid'] = sid
    _body = {}
    while not done.is_set():
        _cookie['nonce'] = aes.encrypt(str(time.time()).encode())
        if mode == 'get':
            _transfer(
                iqueue,
                client,
                'GET',
                _cookie,
                _body,
                aes,
                done
            )
        else:
            _req_data = get_equeue(equeue, aes, done)
            if _req_data is None:
                break
            _req_tokenid, _req_token = _req_data

            if settings.method == 'GET':
                _cookie['tokenid'] = _req_tokenid
                _cookie['token'] = _req_token
            else:
                _body['tokenid'] = _req_tokenid
                _body['token'] = _req_token
            _transfer(
                iqueue,
                client,
                settings.method,
                _cookie,
                _body,
                aes,
                done
            )
    equeue.put(None)
    print('[D] Transfer closed, mode:', mode)


def client(
    host,
    port,
    forward_url=None,
    resolve=False,
    ipv6=False,
    method=None,
    forward_srv=None,
    no_verify=False,
    buffer_size=None,
    queue_size=None,
    reorder_limit=None
):
    print('[I] Starting client mode.')
    try:
        _sock = socket.create_server(
            (host, port),
            family=socket.AF_INET6,
            backlog=16,
            reuse_port=(sys.platform != 'win32'),
            dualstack_ipv6=True
        )
    except Exception:
        try:
            _sock = socket.create_server(
                (host, port),
                family=socket.AF_INET,
                backlog=16,
                reuse_port=(sys.platform != 'win32')
            )
        except Exception as identifier:
            print('[E] Failed to create socket:', identifier)
            exit(1)
    print('[I] Listening on:', f'{_sock.getsockname()[0]}:{_sock.getsockname()[1]}')
    _sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    _sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
    _sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
    _sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 2)

    while True:
        conn, addr = _sock.accept()
        print('[I] Connection accepted:', addr)
        _child = multiprocessing.Process(
            target=handle_connection,
            args=(
                conn,
                addr,
                forward_url,
                resolve,
                ipv6,
                method,
                forward_srv,
                no_verify,
                buffer_size,
                queue_size,
                reorder_limit
            )
        )
        _child.start()
        threading.Thread(target=lambda ps: ps.join(), args=(_child,)).start()
