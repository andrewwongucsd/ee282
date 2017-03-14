import random



def bbs(seed):
    # Generate p and q, two big Blum prime numbers.
    # n = p * q
    p = 383
    q = 503
    n = p * q
    # s = random.randint(1, n - 1)
    s = int(seed)
    x0 = pow(s, 2, n)
    x = x0
    setmap = {}
    seq = []
    setmap[x] = x
    while True:
        x = pow(x, 2, n)
        if setmap.get(x) is None:
            seq.append( x )
        else:
            break
    return seq

def bbsone(seed):
    seq = bbs(seed)
    ret = ""
    print "len", len(seq)
    for i in xrange(0, 128):
        ret = ret + str(seq[i] % 2)
    return int(ret, 2), ret


if __name__ == '__main__':
    print bbsone(17)
