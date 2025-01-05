class Config(object):
    def __init__(self) -> None:
        self.forward_url = 'http://localhost'
        self.forward_hostn = 'localhost'
        self.forward_port = 80
        self.forward_hosth = 'localhost'
        self.method = 'GET'
        self.forward_srv = '127.0.0.1:22'
        self.max_sessions = 10
        self.buffer_size = 32768
        self.queue_size = 10
        self.reorder_limit = 20


def find_packet(
    target_id: int,
    input_queue,
    reorder_buffer: list[tuple[int, bytes]],
    reorder_limit: int
):
    _item = input_queue.get(timeout=10.0)
    if _item is None:
        raise Exception('Abort')
    if _item[0] < target_id:
        print('[W] Received a duplicated packet, ignored.')
        return find_packet(target_id, input_queue, reorder_buffer, reorder_limit)
    if _item[0] != target_id:
        if len(reorder_buffer) > reorder_limit:
            print('[D] Reorder queue is full:', [i[0] for i in reorder_buffer])
            raise Exception('Packets offset too big')

        reorder_buffer.append(_item)
        reorder_buffer.sort(key=lambda i: i[0])

        return find_packet(target_id, input_queue, reorder_buffer, reorder_limit)
    else:
        return _item
