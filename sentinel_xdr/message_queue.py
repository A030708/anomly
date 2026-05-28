from queue import Queue, Empty

_event_queue = Queue()


def enqueue_event(event_id):
    _event_queue.put(event_id)


def dequeue_event(timeout=1):
    try:
        return _event_queue.get(timeout=timeout)
    except Empty:
        return None


def mark_done():
    _event_queue.task_done()
