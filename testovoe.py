import sys

def read_non_empty_line():
    while True:
        line = sys.stdin.readline()
        if not line:
            return None
        line = line.strip()
        if line != "":
            return line

def main():
    line = read_non_empty_line()
    if line is None:
        return
    n = int(line)

    parents = []
    for _ in range(max(0, n-1)):
        line = read_non_empty_line()
        if line is None:
 
            return
        parents.append(int(line))

    a = []
    while len(a) < n:
        line = sys.stdin.readline()
        if not line:
            break
        parts = line.strip().split()
        if not parts:
            continue
        for x in parts:
            if len(a) < n:
                a.append(int(x))
            else:
                break
    if len(a) < n:

        return

    children = [[] for _ in range(n)]
    for i, p in enumerate(parents, start=1):
        children[p].append(i)

    total = 0

    for u in range(n):
        s = 0
        for v in children[u]:
            s += a[v]
        op = -a[u] + s
        total += abs(op)

    print(total)

if __name__ == "__main__":
    main()
