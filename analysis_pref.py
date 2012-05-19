#!/usr/bin/python
import sys
import math
import os
import string

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

        parser.add_option("-p", "--path",
                          type="str", default=os.curdir,
                          dest="path",
                          help="Specify path for burst sample files")

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

#        if len(args) == 0:
#            print >> sys.stderr, "No input file specified."
#            sys.exit(1)

        self.filter = sample_filter.from_str(opts.filter)
#        self.ifile_name = args[0]
        self.line_size = opts.line_size
        self.path = opts.path

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
#        print >> sys.stderr, file_name
        return None

    if usf_file.header.flags & pyusf.USF_FLAG_TRACE:
        print >> sys.stderr, "Error: Specified file is a trace."
        return None

    if not usf_file.header.line_sizes & line_size:
        print >> sys.stderr, \
            "Eror: Specified line size does not exist in sample file."
        return None

    return usf_file

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

#    c = 0
#    avg_stride_count = 0
#    for (pc, stride_hist) in pc_stride_hist.items():
        
#        for (stride, count) in stride_hist.items():
#            if stride == 0 or count == 1:
#                continue
#            avg_stride_count +=  count
#            c += 1 
 
#    avg_stride_count = math.floor(float(avg_stride_count) / float(c))

    for (pc, stride_hist) in pc_stride_hist.items():
        
        for (stride, count) in stride_hist.items():
            if stride == 0 or count == 1: #< avg_stride_count: # 10:
                continue
            
            if not hist.has_key(pc):
                hist[pc]= {}

            hist[pc][stride] = count

    return hist


def rdist_hist_after_prefetching(burst_hists, pref_pcs):

    hist = {}

    for (pc_rdist_hist, pc_stride_hist, pc_freq_hist, pc_time_hist) in burst_hists:
        
#       comm_pc = pc_freq_hist.items()
#       comm_pc.sort(key=lambda x: x[1], reverse=True)

        reduced_pc_stride_hist = reduce_stride_hist(pc_stride_hist)

#        total_samples = 0
#        for (pc, count) in comm_pc:
#            total_samples += count
        
#        for (pc, count) in comm_pc:

#            if pc in reduced_pc_stride_hist:
#                stride_hist = reduced_pc_stride_hist[pc]

                #if len(stride_hist) <= 2:
#                if len(stride_hist) == 1:
#                    pref_pcs.append(pc)

#        for pc in pref_pcs:
#            if pc in reduced_pc_stride_hist:
#                if len(reduced_pc_stride_hist[pc]) > 1:
#                    pref_pcs.remove(pc)
#                    continue
#            else:
#                pref_pcs.remove(pc)
#                continue
            
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
                pc_recur_hist[pc][sd] = pc_recur_hist[pc].get(sd, 0) + count
    
    return [pc_sdist_hist, pc_recur_hist]

def prefetchable_pcs(burst_hists):

    sdist_recur_list = generate_per_pc_sdist_recurrence_hist(burst_hists)

    pc_sdist_hist = sdist_recur_list[0]

    pc_recur_hist = sdist_recur_list[1]

    pref_pcs = []

    for (pc, sdist_hist) in pc_sdist_hist.items():
    
        if max(sdist_hist.keys()) > 1024:
            #in case of a dangling pointer, there will be no entry in pc_recur_hist
            if pc in pc_recur_hist:
                if max(pc_recur_hist[pc].keys()) < 512:
                    pref_pcs.append(pc)
                #prefetch but dont set eviction bits
                elif len(pc_recur_hist[pc].keys()) > 1:
                    pref_pcs.append(pc)
#                else:
#                    print pc_recur_hist[pc]
            else:
                pref_pcs.append(pc)


    for (pc_rdist_hist, pc_stride_hist, pc_freq_hist, pc_time_hist) in burst_hists:
        
        reduced_pc_stride_hist = reduce_stride_hist(pc_stride_hist)

        remove_pcs = []

        for pc in pref_pcs:

            if pc in reduced_pc_stride_hist:
                if len(reduced_pc_stride_hist[pc]) > 1:
                    remove_pcs.append(pc)
            else:
                remove_pcs.append(pc)

        for pc in remove_pcs:
            pref_pcs.remove(pc)

    return pref_pcs

def build_global_prefetchable_pcs(burst_hists, global_pc_stride_hist, global_prefetchable_pcs, pref_pcs):

    for (pc_rdist_hist, pc_stride_hist, pc_freq_hist, pc_time_hist) in burst_hists:

        reduced_pc_stride_hist = reduce_stride_hist(pc_stride_hist)

        for pc in pref_pcs:
            
            if pc in global_pc_stride_hist:
                if len(global_pc_stride_hist[pc]) > 1:
                    pref_pcs.remove(pc)
                    if pc in global_prefetchable_pcs:
                        global_prefetchable_pcs.remove(pc)

                for stride in reduced_pc_stride_hist[pc].keys():

                    if stride in global_pc_stride_hist[pc].keys():
                        global_pc_stride_hist[pc][stride] += reduced_pc_stride_hist[pc][stride]
                    else:
                        global_pc_stride_hist[pc][stride] = stride
                    
    
            else:
                
                global_pc_stride_hist[pc] = reduced_pc_stride_hist[pc]
            
                


def main():
    conf = Conf()

    listing = os.listdir(conf.path)

    cache_size_range = default_range_func()

    win_count = 0

    mr = {}

    mr_w_pf = {}

    pref_pcs_win = {}

    global_pc_stride_hist = {}
    
    global_prefetchable_pcs = []

    for infile in listing:

        infile = conf.path + infile

        usf_file = open_sample_file(infile, conf.line_size)
        
        if usf_file == None:

            continue

        try:
            burst_hists = utils.usf_read_events(usf_file,
                                                line_size=conf.line_size,
                                                filter=conf.filter)

        except IOError, e:
            continue

        usf_file.close()

        pref_pcs = prefetchable_pcs(burst_hists)
                
        build_global_prefetchable_pcs(burst_hists, global_pc_stride_hist, global_prefetchable_pcs, pref_pcs)

        for pc in pref_pcs:
            if not pc in global_prefetchable_pcs:
                global_prefetchable_pcs.append(pc);


    for infile in listing:

        infile = conf.path + infile

        usf_file = open_sample_file(infile, conf.line_size)
        
        if usf_file == None:

            continue

        try:
            burst_hists = utils.usf_read_events(usf_file,
                                                line_size=conf.line_size,
                                                filter=conf.filter)

        except IOError, e:
            continue

        usf_file.close()

        cache_size_range = map(lambda x: x / conf.line_size, cache_size_range)

        rdist_hist = rdist_hist_original(burst_hists)

        win_mr = lrumodel.miss_ratio_range([rdist_hist], cache_size_range, filtered_rdist_hist_list = [rdist_hist])
        
        pref_pcs = prefetchable_pcs(burst_hists)

        for pc in pref_pcs:
            if not pc in global_prefetchable_pcs:
                pref_pcs.remove(pc);

        rdist_hist_w_pf = rdist_hist_after_prefetching(burst_hists, pref_pcs)
    
        win_mr_w_pf = lrumodel.miss_ratio_range([rdist_hist], cache_size_range, filtered_rdist_hist_list = [rdist_hist_w_pf])

        cache_size_range = map(lambda x: x * conf.line_size, cache_size_range)

        for cache_size in cache_size_range:
            mr[cache_size] = mr.get(cache_size, 0) + win_mr._getitem__(cache_size)

        for cache_size in cache_size_range:
             mr_w_pf[cache_size] = mr_w_pf.get(cache_size, 0) + win_mr_w_pf._getitem__(cache_size)

        win_count += 1

#    print pref_pcs_win

#    print global_prefetchable_pcs

    for (cache_size, miss_ratio) in mr.items():
        mr[cache_size] = float(mr.get(cache_size, 0)) / float(win_count)

    for (cache_size, miss_ratio) in mr_w_pf.items():
        mr_w_pf[cache_size] = float(mr_w_pf.get(cache_size, 0)) / float(win_count)

    mr_items = mr.items()
    mr_items.sort(lambda (k0, v0), (k1, v1): cmp(k0, k1))

    mr_w_pf_items = mr_w_pf.items()
    mr_w_pf_items.sort(lambda (k0, v0), (k1, v1): cmp(k0, k1))

    print "#cache size, fetch ratio, miss ratio (after prefetching)"

    for (cache_size, miss_ratio) in mr_items:
        print"%ld %lf %lf"%(cache_size, miss_ratio, mr_w_pf[cache_size])


if __name__ == "__main__":
    main()

