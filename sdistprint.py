#!/usr/bin/python
import sys
import math
import os

from optparse import OptionParser

from uart.hist import Hist
import uart.sample_filter as sample_filter

import pyusf
import lrumodel
import utils
import missratio

__version__ = "$Revision$"

class Conf:
    def __init__(self):
        parser = OptionParser("usage: %prog [OPTIONS...] INFILE")

        parser.add_option("-l", "--line-size",
                          type="int", default="64",
                          dest="line_size",
                          help="Use a specific line size.")

        parser.add_option("-f", "--filter",
                          type="str", default="all()",
                          dest="filter",
                          help="Filter for events to display in histogram.")

        parser.add_option("--help-filters",
                          action="callback", callback=self.help_filters,
                          help="Display help about the filter language.")


        (opts, args) = parser.parse_args()

        if opts.line_size <= 0 or \
                opts.line_size & (opts.line_size - 1) != 0:
            print >> sys.stderr, "Invalid line size specified."
            sys.exit(1)

        if len(args) == 0:
            print >> sys.stderr, "No input file specified."
            sys.exit(1)

        self.filter = sample_filter.from_str(opts.filter)
        self.ifile_name = args[0]
        self.line_size = opts.line_size

    def help_filters(self, option, opt, value, parser):
        sample_filter.usage()
        sys.exit(0)

def pow2(x):
    return int(math.pow(2, x))

def pow2_range(l, u):
    return map(pow2, range(l, u))

def default_range_func():
    return pow2_range(10, 24)

def open_sample_file(file_name, line_size):
    try:
        usf_file = pyusf.Usf()
        usf_file.open(file_name)
    except IOError, e:
        print >> sys.stderr, "Error: %s" % str(e)
        sys.exit(1)

    if usf_file.header.flags & pyusf.USF_FLAG_TRACE:
        print >> sys.stderr, "Error: Specified file is a trace."
        sys.exit(1)

    if not usf_file.header.line_sizes & line_size:
        print >> sys.stderr, \
            "Eror: Specified line size does not exist in sample file."
        sys.exit(1)

    return usf_file

#def generate_sdist_hist(burst_hists):
#    hist = {}
#    for (rdists, filtered_rdists) in burst_hists:
#        r2s = lrumodel.lru_sdist(rdists)
#        for (rdist, count) in filtered_rdists.items():
#            sdist = r2s[rdist]
#            hist[sdist] = hist.get(sdist, 0) + count

#    return hist

def generate_sdist_hist(rdist_hist):
    hist = {}
    r2s = lrumodel.lru_sdist(rdist_hist)
    for (rdist, count) in rdist_hist.items():
        sdist = r2s[rdist]
        hist[sdist] = hist.get(sdist, 0) + count

    return hist

def print_stride_info(burst_hists):

    for (pc_rdist_hist, pc_stride_hist, pc_freq_hist, pc_time_hist) in burst_hists:
        
        comm_pc = pc_freq_hist.items()
        comm_pc.sort(key=lambda x: x[1], reverse=True)

        for (pc, count) in comm_pc:
            print"pc: %lx count: %d\n"%(pc, count)
            stride_cnt_list = pc_stride_hist[pc].items()
            stride_cnt_list.sort(key=lambda x: x[1], reverse=True)
            
            for (stride, count) in stride_cnt_list:
                print"stride: %d, %d\n"%(stride, count)

def rdist_hist_original(burst_hists):
    
    hist = {}

    for (pc_rdist_hist, pc_stride_hist, pc_freq_hist, pc_time_hist) in burst_hists:
        
        for (pc, rdist_hist) in pc_rdist_hist.items():
            for (rdist, count) in rdist_hist.items():
                hist[rdist] = hist.get(rdist, 0) + count

    return hist

def reduce_stride_hist(pc_stride_hist):
    
    hist = {}

    c = 0
    avg_stride_count = 0
    for (pc, stride_hist) in pc_stride_hist.items():
        
        for (stride, count) in stride_hist.items():
            if stride == 0 or count == 1:
                continue
            avg_stride_count +=  count
            c += 1 
 
    avg_stride_count = math.floor(float(avg_stride_count) / float(c))

    for (pc, stride_hist) in pc_stride_hist.items():
        
        for (stride, count) in stride_hist.items():
            if stride == 0 or count == 1: #avg_stride_count: # 10:
                continue
            
            if not pc in hist:
                hist[pc]= {}

            hist[pc][stride] = count

    return hist


def rdist_hist_after_prefetching(burst_hists, pref_pcs):
    
    hist = {}

    for (pc_rdist_hist, pc_stride_hist, pc_freq_hist, pc_time_hist) in burst_hists:
        
#       comm_pc = pc_freq_hist.items()
#       comm_pc.sort(key=lambda x: x[1], reverse=True)

#        reduced_pc_stride_hist = reduce_stride_hist(pc_stride_hist)

#        total_samples = 0
#        for (pc, count) in comm_pc:
#            total_samples += count
        
#        for (pc, count) in comm_pc:

#            if pc in reduced_pc_stride_hist:
#                stride_hist = reduced_pc_stride_hist[pc]

                #if len(stride_hist) <= 2:
#                if len(stride_hist) == 1:
#                    pref_pcs.append(pc)

        for pc in pref_pcs:
            if len(pc_stride_hist[pc]) != 1:
                pref_pcs.remove(pc)

        for (pc, rdist_hist) in pc_rdist_hist.items():
            for (rdist, count) in rdist_hist.items():
                if pref_pcs.count(pc) == 0:
                    hist[rdist] = hist.get(rdist, 0) + count

    if len(hist) == 0:
        for (pc, rdist_hist) in pc_rdist_hist.items():
            for (rdist, count) in rdist_hist.items():
                    hist[rdist] = 0

    return hist

def generate_per_pc_sdist_recurrence_hist(burst_hists):

    pc_sdist_hist = {}
    pc_recur_hist = {}

    for (pc_rdist_hist, pc_stride_hist, pc_freq_hist, pc_time_hist) in burst_hists:

        rdist_hist = rdist_hist_original(burst_hists)

        r2s = lrumodel.lru_sdist(rdist_hist)

        for (pc, rdist_hist) in pc_rdist_hist.items():

            if not pc in pc_sdist_hist:
                pc_sdist_hist[pc] = {}

            for (rdist, count) in rdist_hist.items():
                sd  = int(round(r2s[rdist]))
                pc_sdist_hist[pc][sd] = pc_sdist_hist.get(sd, 0) + count

        for (pc, time_hist) in pc_time_hist.items():

            if not pc in pc_recur_hist:
                pc_recur_hist[pc] = {}

            for (recur, count) in time_hist.items():

                if not recur in r2s:
                    recur_c = min(r2s.keys(), key=lambda k: abs(k-recur))
#                    print"recur %d -> %d"%(recur, recur_c)
                    recur = recur_c

                sd  = int(round(r2s[recur]))
                pc_recur_hist[pc][sd] = pc_recur_hist.get(sd, 0) + count
    
    return [pc_sdist_hist, pc_recur_hist]

def prefetchable_pcs(burst_hists):

    sdist_recur_list = generate_per_pc_sdist_recurrence_hist(burst_hists)

    pc_sdist_hist = sdist_recur_list[0]

    pc_recur_hist = sdist_recur_list[1]

    pref_pcs = []

    for (pc, sdist_hist) in pc_sdist_hist.items():
    
        if max(sdist_hist.keys()) > 1024 and max(pc_recur_hist[pc].keys()) < 512:
            pref_pcs.append(pc)

    return pref_pcs




def main():
    conf = Conf()
    usf_file = open_sample_file(conf.ifile_name, conf.line_size)
    burst_hists = utils.usf_read_events(usf_file,
                                        line_size=conf.line_size,
                                        filter=conf.filter)
    usf_file.close()

    cache_size_range = default_range_func()

    line_size = 64

    cache_size_range = map(lambda x: x / line_size, cache_size_range)

    pref_pcs = prefetchable_pcs(burst_hists)

    rdist_hist = rdist_hist_original(burst_hists)

    mr = lrumodel.miss_ratio_range([rdist_hist], cache_size_range, filtered_rdist_hist_list = [rdist_hist])

    rdist_hist_w_pf = rdist_hist_after_prefetching(burst_hists, pref_pcs)
    
    mr_w_pf = lrumodel.miss_ratio_range([rdist_hist], cache_size_range, filtered_rdist_hist_list = [rdist_hist_w_pf])

    print mr

    print mr_w_pf

#    print_stride_info(burst_hists)

#    data = hist.items()
#    data.sort(key=lambda x: x[0])

#    l1_sd_samples = 0
#    l2_sd_samples = 0
#    l3_sd_samples = 0
#    mem_sd_samples = 0
#    non_l1_sd_samples = 0
#    total_sd_samples = 0

#    for (sd, count) in data:
        
#        total_sd_samples += count
#        if sd < 512: # 512 number of cache lines in 32kB L1 cache
#           l1_sd_samples += count
#            continue
#        elif sd < 8192:
#            l2_sd_samples += count
#        elif sd < 98304:
#            l3_sd_samples += count
#        else:
#            mem_sd_samples += count
#            
#        non_l1_sd_samples += count
#                    
#    l1_bound_samples = (float(l1_sd_samples)/float(total_sd_samples)*100)
#    l2_bound_samples = (float(l2_sd_samples)/float(non_l1_sd_samples)*100)
#    l3_bound_samples = (float(l3_sd_samples)/float(non_l1_sd_samples)*100)
#    mem_bound_samples = (float(mem_sd_samples)/float(non_l1_sd_samples)*100)
#    non_l1_bound_samples = (float(non_l1_sd_samples)/float(total_sd_samples) * 100)
#    print "L1 bound memory accesses %.2f %% of total"%(l1_bound_samples)
#    print "L2 bound memory accesses %.2f %% of %.2f %%"%(l2_bound_samples, non_l1_bound_samples)
#    print "L3 bound memory accesses %.2f %% of %.2f %%"%(l3_bound_samples, non_l1_bound_samples)
#    print "Memory bound memory accesses %.2f %% of %.2f %%"%(mem_bound_samples, non_l1_bound_samples)

if __name__ == "__main__":
    main()

