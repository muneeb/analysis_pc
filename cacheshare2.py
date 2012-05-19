#!/usr/bin/python
import sys
import math
import copy
import lrumodel

from uart.utils  import print_and_exit
from uart.interp import LinearInterp

class Args:
    def __init__(self):
        self.hist_file_name1 = ""
        self.hist_file_name2 = ""
        self.cpi1 = 0.0
        self.cpi2 = 0.0
        self.mix1 = 0.0
        self.mix2 = 0.0
        self.cache_size = 2 * 1024 * 1024 / 64

    def parse(self):
        if not (len(sys.argv) == 7 or len(sys.argv) ==  8):
            print_and_exit("Usage: %s <hist1> <hist2> <l1_mr1> <l1_mr2>" + \
                           " <mix1> <mix2> <accesses1> accesses2> [<cache_size>]" % sys.argv[0])

        if len(sys.argv) >= 7:
            self.hist_file_name1 = sys.argv[1]
            self.hist_file_name2 = sys.argv[2]
            self.l1_mr1 = float(sys.argv[3])
            self.l1_mr2 = float(sys.argv[4])
            self.mix1 = float(sys.argv[5])
            self.mix2 = float(sys.argv[6])

        if len(sys.argv) >= 8:
            self.cache_size = int(sys.argv[7])


def load_hist(file_name):
    try:
        file = open(file_name, "r")
    except IOError, e:
        print_and_exit(str(e))

    hist = eval(file.read())

    file.close()
    return hist


def fixed_point(f, x0, tol, max_iters = 32):
    x_p = x0
    while max_iters > 0:
        x = f(x_p)
        if math.fabs(x - x_p) < tol:
            break
        x_p = x
        max_iters -= 1

    if max_iters == 0:
        print >> sys.stderr, "WARNING: fixed_point: max_iters reached (%f, %f)" % (x, x_p)

    return x

def fixed_point_test(f, x0_1, x0_2, tol):
    x1 = fixed_point(f, x0_1, tol)
    x2 = fixed_point(f, x0_2, tol)
    if math.fabs(x1 - x2) >= tol:
        print >> sys.stderr, "WARNING: Multiple fixed points (%f, %f)" % (x1, x2)
    return (x1 + x2) / 2


def fixed_point2d(f1, f2, x0, tol, max_iters = 32):
    x1_p = x0
    while max_iters > 0:
        x2 = f1(x1_p)
        x1 = f2(x2)
        if math.fabs(x1 - x1_p) < tol:
            break
        x1_p = x1
        max_iters -= 1

    if max_iters == 0:
        print >> sys.stderr, "WARNING: fixed_point2d: max iters reached (%f, %f)" % (x1, x1_p)

    return (x2, x1)


def hist_est(hist, mix1, mix2, cpi1, cpi2):
    hist_ = {}
    q1 = 1.0 + (mix2 / mix1) * (cpi1 / cpi2)
    for r, c in hist.items():
        rdist = int(round(r * q1))
        hist_[rdist] = hist_.get(rdist, 0) + c
    return hist_

def hist_add(hist1, hist2):
    hist = copy.copy(hist1)
    for r, c in hist2.items():
        hist[r] = hist.get(r, 0) + c
    return hist

def miss_ratio(rdist_hist, esd_func, cache_size):
    ref_count = sum(rdist_hist.values())
    hit_count = 0.0
    for rdist, count in rdist_hist.items():
        esd = esd_func(rdist)
        if esd < cache_size:
            hit_count += count
    return 1.0 - hit_count / ref_count


class CacheShare_slow:
    def __init__(self, hist_file_name1, hist_file_name2,
                 mix1, mix2, cpi_func1 = None, cpi_func2 = None):
        self.mix1 = mix1
        self.mix2 = mix2

        self.hist1 = load_hist(hist_file_name1)
        self.hist2 = load_hist(hist_file_name2)

        if cpi_func1:
            self.cpi_func1 = cpi_func1
        else:
            self.cpi_func1 = default_cpi_func

        if cpi_func2:
            self.cpi_func2 = cpi_func2
        else:
            self.cpi_func2 = default_cpi_func

    def mratio1(self, cpi1, cpi2, cache_size):
        hist1_hat = hist_est(self.hist1, self.mix1, self.mix2, cpi1, cpi2)
        hist2_hat = hist_est(self.hist2, self.mix2, self.mix1, cpi2, cpi1)
        hist_hat = hist_add(hist1_hat, hist2_hat)
        return lrumodel.miss_ratio([hist_hat], [hist1_hat], True)[cache_size]

    def mratio2(self, cpi1, cpi2, cache_size):
        hist1_hat = hist_est(self.hist1, self.mix1, self.mix2, cpi1, cpi2)
        hist2_hat = hist_est(self.hist2, self.mix2, self.mix1, cpi2, cpi1)
        hist_hat = hist_add(hist1_hat, hist2_hat)
        return lrumodel.miss_ratio([hist_hat], [hist2_hat], True)[cache_size]

    def cpi1(self, cpi1, cpi2, cache_size):
        return self.cpi_func1(self.mratio1(cpi1, cpi2, cache_size), self.mix1)

    def cpi2(self, cpi1, cpi2, cache_size):
        return self.cpi_func2(self.mratio2(cpi1, cpi2, cache_size), self.mix2)

    def CPI1(self, cpi2, cache_size, tol = 0.001):
        f = lambda cpi1: self.cpi1(cpi1, cpi2, cache_size)
        cpi0_1 = self.cpi_func1(0, self.mix1)
        cpi0_2 = self.cpi_func2(1.0, self.mix1)
        return fixed_point_test(f, cpi0_1, cpi0_2, tol)

    def CPI2(self, cpi1, cache_size, tol = 0.001):
        f = lambda cpi2: self.cpi2(cpi1, cpi2, cache_size)
        cpi0_1 = self.cpi_func1(0, self.mix2)
        cpi0_2 = self.cpi_func2(1.0, self.mix2)
        return fixed_point_test(f, cpi0_1, cpi0_2, tol)



class CacheShare:
    def __init__(self, hist_file_name1, hist_file_name2,
                 mix1, mix2, cpi_func1 = None, cpi_func2 = None):
        self.mix1 = mix1
        self.mix2 = mix2

        self.hist1 = load_hist(hist_file_name1)
        self.hist2 = load_hist(hist_file_name2)

        self.esd1 = LinearInterp(lrumodel.lru_sdist(self.hist1, True).items())
        self.esd2 = LinearInterp(lrumodel.lru_sdist(self.hist2, True).items())

        self.n1 = float(sum(self.hist1.values()))
        self.n2 = float(sum(self.hist2.values()))
        self.n = self.n1 + self.n2

        default_cpi_func = lambda mr, mix: 1.0 + 300.0 * mix * mr

        if cpi_func1:
            self.cpi_func1 = cpi_func1
        else:
            self.cpi_func1 = default_cpi_func

        if cpi_func2:
            self.cpi_func2 = cpi_func2
        else:
            self.cpi_func2 = default_cpi_func

    def __esd_hat(self, rdist, cpi1, cpi2, esd1, esd2, mix1, mix2, n1, n2):
        q1 = 1.0 + (mix2 / mix1) * (cpi1 / cpi2)
        q2 = 1.0 + (mix1 / mix2) * (cpi2 / cpi1)

        esd = q1 * (n1 / self.n) * esd1[rdist] + \
              q2 * (n2 / self.n) * esd2[rdist * (q1 - 1.0)]
        return esd

    def esd1_hat(self, rdist, cpi1, cpi2):
        return self.__esd_hat(rdist, cpi1, cpi2, self.esd1, self.esd2,
                              self.mix1, self.mix2, self.n1, self.n2)

    def esd2_hat(self, rdist, cpi1, cpi2):
        return self.__esd_hat(rdist, cpi2, cpi1, self.esd2, self.esd1,
                              self.mix2, self.mix1, self.n2, self.n1)

    def __mratio(self, cpi1, cpi2, cache_size, esd_func, hist, n):
        hit_count = 0.0
        for rdist, count in hist.items():
            esd = esd_func(rdist, cpi1, cpi2)
            if esd < cache_size:
                hit_count += count
        return 1.0 - hit_count / n

    def mratio1(self, cpi1, cpi2, cache_size):
        return self.__mratio(cpi1, cpi2, cache_size, self.esd1_hat, self.hist1, self.n1)

    def mratio2(self, cpi1, cpi2, cache_size):
        return self.__mratio(cpi1, cpi2, cache_size, self.esd2_hat, self.hist2, self.n2)

    def cpi1(self, cpi1, cpi2, cache_size):
        return self.cpi_func1(self.mratio1(cpi1, cpi2, cache_size), self.mix1)

    def cpi2(self, cpi1, cpi2, cache_size):
        return self.cpi_func2(self.mratio2(cpi1, cpi2, cache_size), self.mix2)

    def CPI1(self, cpi2, cache_size, tol = 0.001):
        f = lambda cpi1: self.cpi1(cpi1, cpi2, cache_size)
        cpi0_1 = self.cpi_func1(0, self.mix1)
        cpi0_2 = self.cpi_func2(1.0, self.mix1)
        return fixed_point_test(f, cpi0_1, cpi0_2, tol)

    def CPI2(self, cpi1, cache_size, tol = 0.001):
        f = lambda cpi2: self.cpi2(cpi1, cpi2, cache_size)
        cpi0_1 = self.cpi_func1(0, self.mix2)
        cpi0_2 = self.cpi_func2(1.0, self.mix2)
        return fixed_point_test(f, cpi0_1, cpi0_2, tol)


def my_cpi_func(mix, l1_mr, l2_mr):
    L1_LATANCY =  1.0
    L2_LATANCY =  10.0
    MEM_LATANCY = 130.0

    l1_hr = 1.0   - l1_mr
    l2_hr = l1_mr - l2_mr

    cpa = L1_LATANCY  * l1_hr +\
          L2_LATANCY  * l2_hr +\
          MEM_LATANCY * l2_mr

    return 1.0 + mix * cpa


def main():
    args = Args()
    args.parse()

    mix1 = args.mix1
    mix2 = args.mix2

    cache_size = args.cache_size

    """
    hist1 = load_hist(args.hist_file_name1)
    hist2 = load_hist(args.hist_file_name2)

    cpi1 = args.l1_mr1
    cpi2 = args.l1_mr2
    hist1_hat = hist_est(hist1, mix1, mix2, cpi1, cpi2)
    hist2_hat = hist_est(hist2, mix2, mix1, cpi2, cpi1)
    hist_hat = hist_add(hist1_hat, hist2_hat)
    """

    cpi_func1 = lambda mr, mix: my_cpi_func(mix, args.l1_mr1, mr)
    cpi_func2 = lambda mr, mix: my_cpi_func(mix, args.l1_mr2, mr)

    esd = CacheShare_slow(args.hist_file_name1, args.hist_file_name2,
                     mix1, mix2, cpi_func1, cpi_func2)

    f1 = lambda x1: esd.CPI1(x1, cache_size)
    f2 = lambda x2: esd.CPI2(x2, cache_size)
    cpi1, cpi2 = fixed_point2d(f1, f2, 1.0, 0.0001)

    mr1 = esd.mratio1(cpi1, cpi2, cache_size)
    mr2 = esd.mratio2(cpi1, cpi2, cache_size)

    print cpi1, cpi2, mr1, mr2

if __name__ == "__main__":
    main()
