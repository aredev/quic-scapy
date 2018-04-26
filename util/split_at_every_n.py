def split_at_nth_char(a, n=2):
    return [a[i:i + n] for i in range(0, len(a), n)]
