import re

def parse_log_entry(line: str):
    pattern = r'(\S+) - - \[([^\]]+)\] "(\S+) (\S+) HTTP/\d\.\d" (\d{3}) (\S+) "([^"]*)" "([^"]*)"'
    match = re.match(pattern, line.strip())
    if match:
        return {
            "ip": match.group(1),
            "timestamp": match.group(2),
            "method": match.group(3),
            "path": match.group(4),
            "code": int(match.group(5)),
            "response_size": int(match.group(6)) if match.group(6).isdigit() else 0,
            "referer": match.group(7),
            "user_agent": match.group(8)
        }
    else:
        return None

class LogEntry:
    def __init__(self, dictionary):
        self.ip = dictionary["ip"]
        self.timestamp = dictionary["timestamp"]
        self.method = dictionary["method"]
        self.path = dictionary["path"]
        self.code = int(dictionary["code"])
        self.response_size = int(dictionary["response_size"])
        self.referer = dictionary["referer"]
        self.user_agent = dictionary["user_agent"]

    @property
    def is_error(self):
        return 400 <= self.code < 600

def load_log_entries(file_path: str):
    with open(file_path, 'r') as f:
        for line in f:
            d = parse_log_entry(line)
            if d is not None:
                yield LogEntry(d)

def collect_errors_by_type(log_entry: LogEntry, errors_dict=None):
    if errors_dict is None:
        errors_dict = {}
    if 400 <= log_entry.code < 500:
        errors_dict.setdefault("client", []).append(log_entry)
    if 500 <= log_entry.code < 600:
        errors_dict.setdefault("server", []).append(log_entry)
    return errors_dict

def generate_frequent_ips_report(log_iterator, /, *, min_requests=100):
    ip_counts = {}
    for log in log_iterator:
        ip_counts[log.ip] = ip_counts.get(log.ip, 0) + 1
    return {ip: count for ip, count in ip_counts.items() if count > min_requests}

def _load_for_globals():
    try:
        with open("dummy_path.log", "r") as f:
            lines = f.readlines()
    except Exception:
        lines = []
    entries = []
    for line in lines:
        d = parse_log_entry(line)
        if d is not None:
            entries.append(LogEntry(d))
    return entries

class _GlobalsProxy:
    @property
    def TOP_5_REQUESTS(self):
        logs = _load_for_globals()
        return sorted(
            filter(lambda log: 200 <= log.code < 300, logs),
            key=lambda log: log.response_size,
            reverse=True
        )[:5]
    @property
    def PATH_ITERATOR(self):
        logs = _load_for_globals()
        return map(
            lambda log: log.path,
            filter(lambda log: log.method == "POST" and 400 <= log.code < 500, logs)
        )

_globals = _GlobalsProxy()
TOP_5_REQUESTS = _globals.TOP_5_REQUESTS
PATH_ITERATOR = _globals.PATH_ITERATOR

def create_analyzer(filter_func, aggregate_func):
    def analyzer(log_iterator):
        filtered = filter(filter_func, log_iterator)
        return aggregate_func(filtered)
    return analyzer

def build_path_tree(log_entries: list):
    tree = {}
    def add_path(tree, parts):
        if not parts:
            return
        head = parts[0]
        if head not in tree:
            tree[head] = {"hits": 0, "children": {}}
        if len(parts) == 1:
            tree[head]["hits"] += 1
        else:
            add_path(tree[head]["children"], parts[1:])
    for log in log_entries:
        parts = [p for p in log.path.strip("/").split("/") if p]
        add_path(tree, parts)
    return tree

def cache_result(func):
    cache = {}
    def wrapper(*args, **kwargs):
        key = (args, tuple(sorted(kwargs.items())))
        if key not in cache:
            cache[key] = func(*args, **kwargs)
        return cache[key]
    return wrapper