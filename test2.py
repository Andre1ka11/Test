import re

def parse_log_entry(line: str):
    pattern = r'(\S+) - - \[([^\]]+)\] "(\S+) (\S+) HTTP/\d\.\d" (\d{3}) (\S+) "([^"]*)" "([^"]*)"' 
    match = re.match(pattern, line.strip())
    mydict = dict()
    if match:
            mydict["ip"] = match.group(1)          
            mydict["timestamp"] = match.group(2)    
            mydict["method"] = match.group(3)      
            mydict["path"] = match.group(4)         
            mydict["code"]= match.group(5)         
            mydict["response_size"]= int(match.group(6)) if match.group(6).isdigit() else 0 
            mydict["referer"]= match.group(7)   
            mydict["user_agent"] = match.group(8)

            return mydict
    else:
        return None

class LogEntry:
    def __init__(self, dictionary):
          self.ip = dictionary["ip"]
          self.timestamp = dictionary["timestamp"]
          self.method = dictionary["method"]
          self.path = dictionary["path"]
          self.code = dictionary["code"]
          self.response_size = dictionary["response_size"]
          self.referer = dictionary["referer"]
          self.user_agent = dictionary["user_agent"]


    @property
    def is_error(self):
        if int(self.code) >= 400 and int(self.code) <= 599:
            return True
        else:
            return False

def generator(file_path):
    with open( file_path, 'r') as file:
        for line in file:
            mydict = parse_log_entry(line)
            if mydict != None:
                log = LogEntry(parse_log_entry(line))
                yield log 

#for log in generator('fail.txt'):  #то есть генератор работает как итератор и для каждого конкретного итерирумого объекта 
                                    #возвращет наш объект а не просто сразу при вызове просто так как generator('fail.txt')
 #    print(log.ip)

def collect_errors_by_type(log_entry: LogEntry, errors_dict = None):
    if errors_dict == None:
          errors_dict = dict()
    if int(log_entry.code) >= 400 and int(log_entry.code) <=499:
         errors_dict.setdefault("client", []).append(log_entry)
    if int(log_entry.code) >= 500 and int(log_entry.code) <=599:
         errors_dict.setdefault("server", []).append(log_entry)
    
    return errors_dict

def generate_frequent_ips_report(log_iterator, /, *, min_requests=100):
     filter_dict = dict()
     help_dict = dict()
     for log in log_iterator:
          if log.ip not in help_dict:
               help_dict[log.ip] = 1
          else:
               help_dict[log.ip] =  help_dict[log.ip] + 1
     
     for key in help_dict:
          if help_dict[key] > min_requests:
               filter_dict[key] = help_dict[key]
    
     return filter_dict



def TOP_5_REQUESTS(log_iterator):
    successful_logs = filter(lambda log: 200 <= int(log.code) < 300, log_iterator)
    top5 = sorted(successful_logs, key=lambda log: log.response_size, reverse=True)[:5]
    return top5


def PATH_ITERATOR(log_iterator):
    client_error_posts = filter(lambda log: log.method == "POST" and 400 <= int(log.code) < 500, log_iterator)
    return map(lambda log: log.path, client_error_posts)


def filter_func(log_entry: LogEntry):
     if log_entry.response_size > 10000:
          return True
     else:
          return False

def aggregate_func(filter_log_iterator):
     summ = 0
     for log in filter_log_iterator:
          summ = summ + log.response_size
     return summ

     
def create_analyzer(filter_func, aggregate_func):
     def analyzer(log_iterator):
           filtered_logs = filter(filter_func, log_iterator)
           result = aggregate_func(filtered_logs)
           return result
     return analyzer


def build_path_tree(log_entries: list[LogEntry]) -> dict:
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
        # удаляем ведущие и лишние слэши
        path_parts = [p for p in log.path.strip("/").split("/") if p]
        add_path(tree, path_parts)

    return tree

def cache_result(func):
    cache = {}

    def wrapper(*args, **kwargs):
        key = (args, tuple(sorted(kwargs.items())))
        if key not in cache:
            cache[key] = func(*args, **kwargs)
        return cache[key]

    return wrapper



          
              
    
     

