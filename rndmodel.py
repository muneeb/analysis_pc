#!/usr/bin/python
import sys
import math
from scipy.optimize import newton
import missratio

def miss_ratio(rdist_hist, filtered_rdist_hist, cache_size_lines):
    ref_count = sum(rdist_hist.values())
    filtered_ref_count = sum(filtered_rdist_hist.values())

    def f(replacements):
        return 1.0 - math.pow(1.0 - 1.0 / cache_size_lines, replacements)

    def hist_misses(miss_ratio, rdist_hist):
        return sum(map(lambda (rdist, count) : count * f(miss_ratio * rdist),
                       rdist_hist.items()))

    def obj(miss_ratio):
        lhs = miss_ratio * ref_count
        rhs = hist_misses(miss_ratio, rdist_hist)
        return lhs - rhs

    mr = newton(obj, 0.1);
    return hist_misses(mr, filtered_rdist_hist) / filtered_ref_count

def miss_ratio_range(rdist_hist_list, cache_size_range,
                     filtered_rdist_hist_list = None):
    if filtered_rdist_hist_list == None:
        filtered_rdist_hist_list = rdist_hist_list

    if len(rdist_hist_list) > 1:
        print >> sys.stderr, "Warning: Random analysis will only be " + \
            "performed for the last burst."


    mr = []
    for cache_size in cache_size_range:
        mr.append((cache_size,
                   miss_ratio(rdist_hist_list[-1],
                              filtered_rdist_hist_list[-1],
                              cache_size)))
    return missratio.MissRatio(mr)
