import threading


def singleton(cls):
    """Decorator to make a class a singleton."""
    instances = {}
    lock = threading.Lock()  # Lock for thread-safe singleton creation

    def get_instance(*args, **kwargs):
        with lock:  # Ensure only one thread can create the instance
            if cls not in instances:
                instances[cls] = cls(*args, **kwargs)
        return instances[cls]

    return get_instance
