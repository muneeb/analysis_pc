#!/usr/bin/python
import sys
import math
import os
import string

import operator

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

    for (pc, stride_hist) in pc_stride_hist.items():
        
        for (stride, count) in stride_hist.items():
            if stride == 0 or count == 1: 
                continue
            
            if not hist.has_key(pc):
                hist[pc]= {}

            hist[pc][stride] = count

    return hist


def rdist_hist_after_prefetching(burst_hists, pref_pcs):

    hist = {}

    for (pc_rdist_hist, pc_stride_hist, pc_freq_hist, pc_time_hist) in burst_hists:
        
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
                    recur = recur_c

                sd  = int(round(r2s[recur]))
                pc_recur_hist[pc][sd] = pc_recur_hist[pc].get(sd, 0) + count

#                pc_recur_hist[pc][recur] = count
    
    return [pc_sdist_hist, pc_recur_hist]

def prefetchable_pcs(burst_hists):

    sdist_recur_list = generate_per_pc_sdist_recurrence_hist(burst_hists)

    pc_sdist_hist = sdist_recur_list[0]

    pc_recur_hist = sdist_recur_list[1]

    pref_pcs = []

    for (pc, sdist_hist) in pc_sdist_hist.items():
    
        #considering L1$ size == 64kB (1024 cache lines)
        if max(sdist_hist.keys()) > 1024:
            #in case of a dangling pointer, there "may" be no entry in pc_recur_hist 
            if pc in pc_recur_hist:
                max_recur = max(pc_recur_hist[pc].keys())
                if  max_recur < 512:
                    pref_pcs.append(pc)
                else:
                    #prefetch but dont set eviction bits - even if there are chances of being evicted without being used, it will still be used some times
                    total_recur_count = sum(pc_recur_hist[pc].itervalues()) 
                    max_recur_freq = float(float(max_recur)/float(total_recur_count) )

                    if max_recur_freq < 0.2:
                        pref_pcs.append(pc)
            else:
                pref_pcs.append(pc)


    return [pref_pcs, pc_sdist_hist, pc_recur_hist]

def build_global_prefetchable_pcs(burst_hists, global_prefetchable_pcs, pref_pcs):

    for pc in pref_pcs:
        if not pc in global_prefetchable_pcs:
            global_prefetchable_pcs.append(pc);
    

def build_global_pc_sdist_recur_hist(global_pc_sdist_hist, global_pc_recur_hist, pc_sdist_hist, pc_recur_hist):

    for (pc, sdist_hist) in pc_sdist_hist.items():
        if pc in global_pc_sdist_hist:
            for (sdist, count) in sdist_hist.items():
                global_pc_sdist_hist[pc][sdist] = global_pc_sdist_hist[pc].get(sdist, 0) + count
        else:
            global_pc_sdist_hist[pc] = {} 
            for (sdist, count) in sdist_hist.items():
                global_pc_sdist_hist[pc][sdist] = count


    for (pc, recur_hist) in pc_recur_hist.items():
        if pc in global_pc_recur_hist:
            for (recur, count) in recur_hist.items():
                global_pc_recur_hist[pc][recur] = global_pc_recur_hist[pc].get(recur, 0) + count
        else:
            global_pc_recur_hist[pc] = {} 
            for (recur, count) in recur_hist.items():
                global_pc_recur_hist[pc][recur] = count

def build_full_pc_stride_hist(burst_hists, full_pc_stride_hist):

    for (pc_rdist_hist, pc_stride_hist, pc_freq_hist, pc_time_hist) in burst_hists:
        
        pc_l = pc_stride_hist.keys()

        for pc in pc_l:
            if pc in full_pc_stride_hist:

                for stride in pc_stride_hist[pc].keys():
                    
                    if stride in full_pc_stride_hist[pc].keys():
                        full_pc_stride_hist[pc][stride] += pc_stride_hist[pc][stride]
                    else:
                        full_pc_stride_hist[pc][stride] = pc_stride_hist[pc][stride]
                        
            else:

                full_pc_stride_hist[pc] = {}
                for stride in pc_stride_hist[pc].keys():
                    full_pc_stride_hist[pc][stride] = pc_stride_hist[pc][stride]


def generate_pref_pcs_info(global_prefetchable_pcs, global_pc_sdist_hist, global_pc_recur_hist, full_pc_stride_hist):

    cache_line_size = 64

    remove_pcs = []

    reduced_full_pc_stride_hist = reduce_stride_hist(full_pc_stride_hist)

    for pc in global_prefetchable_pcs:

        if not pc in reduced_full_pc_stride_hist.keys():
            continue

        pf_type = 'pf'

        #considering L3$ size == 6MB (98304 cache lines)
        if min(global_pc_sdist_hist[pc].keys()) > 98304:
            pf_type = 'nta'

        sorted_x = sorted(reduced_full_pc_stride_hist[pc].iteritems(), key=operator.itemgetter(1), reverse=True)

        max_stride = sorted_x[0][0] 
        max_count = sorted_x[0][1]

        total_stride_count = sum(full_pc_stride_hist[pc].itervalues())

#        sum(full_pc_stride_hist[pc].items(), key= lambda x,y: )

        max_stride_region_count = 0
        max_stride_region = math.floor(float(max_stride) / float(cache_line_size))
                    
        for s,c in full_pc_stride_hist[pc].items():
            
            if math.floor(float(s) / float(cache_line_size)) == max_stride_region:
                max_stride_region_count += c


        if float(float(max_stride_region_count) / float(total_stride_count)) < float(0.5):
            remove_pcs.append(pc)
            continue


        min_r = min(global_pc_recur_hist[pc].keys())


        stride = max_stride

        if (abs(stride) * max_count) <= cache_line_size:
            continue


        sorted_x = sorted(global_pc_recur_hist[pc].iteritems(), key=operator.itemgetter(1), reverse=True)

        weight = 0
        avg_r = 0

        for r, c in sorted_x:
            avg_r += int(r) * int(c)
            weight += int(c)

        avg_r = round(float(avg_r)/ float(weight))

        min_r = sorted_x[0][0]

        if min_r == 0:
            min_r = 1

        if avg_r == 0:
            avg_r = 1
            
        if abs(stride) < cache_line_size:

            no_iters = int(round(float(cache_line_size) / float(abs(stride)) )) - 1

            if no_iters == 0:
                no_iters = 1

            pd = math.ceil(float(150) / float(avg_r * 1.3 * no_iters ))

            if pd == 0:
                pd = 1 

            sd = cache_line_size * pd

        else:
            
            no_iters = 1

            pd = math.ceil(float(150) / float(avg_r * 1.3 * no_iters))

            if pd == 0:
                pd = 1 

            sd = stride * pd

#        if abs(stride) > cache_line_size:
#            sd = stride * math.ceil(float(10) / float(min_r))
#        else:
#            sd = (stride/abs(stride)) * cache_line_size * math.ceil(float(10) / float(min_r))
#            sd = (stride/abs(stride)) * cache_line_size * math.ceil(float(cache_line_size / abs(stride)) / float(min_r))

#        if pf_type == 'nta':
#            sd = 0

        print >> sys.stderr, stride
        print >> sys.stderr, "full:", full_pc_stride_hist[pc]
        print >> sys.stderr, "\n\n\n"
        

        print"%ld:%s:%d"%(pc, pf_type, int(sd))


def main():
    conf = Conf()

    listing = os.listdir(conf.path)

    cache_size_range = default_range_func()

    win_count = 0

    mr = {}

    mr_w_pf = {}

    pref_pcs_win = {}

    full_pc_stride_hist = {}

    global_pc_sdist_hist = {}

    global_pc_recur_hist = {}
    
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

        pref_pcs_sdist_recur_list = prefetchable_pcs(burst_hists)
        
        pref_pcs = pref_pcs_sdist_recur_list[0]

        pc_sdist_hist = pref_pcs_sdist_recur_list[1]
        
        pc_recur_hist = pref_pcs_sdist_recur_list[2]
                
        build_global_prefetchable_pcs(burst_hists, global_prefetchable_pcs, pref_pcs)

        build_full_pc_stride_hist(burst_hists, full_pc_stride_hist)

        build_global_pc_sdist_recur_hist(global_pc_sdist_hist, global_pc_recur_hist, pc_sdist_hist, pc_recur_hist)

#    print >> sys.stderr, full_pc_stride_hist

    generate_pref_pcs_info(global_prefetchable_pcs, global_pc_sdist_hist, global_pc_recur_hist, full_pc_stride_hist)

#    for infile in listing:

#        infile = conf.path + infile

#        usf_file = open_sample_file(infile, conf.line_size)
        
#        if usf_file == None:
#            continue

#        try:
#            burst_hists = utils.usf_read_events(usf_file,
#                                                line_size=conf.line_size,
#                                                filter=conf.filter)

#        except IOError, e:
#            continue

#        usf_file.close()

#        cache_size_range = map(lambda x: x / conf.line_size, cache_size_range)

#        rdist_hist = rdist_hist_original(burst_hists)

#        win_mr = lrumodel.miss_ratio_range([rdist_hist], cache_size_range, filtered_rdist_hist_list = [rdist_hist])
        
#        pref_pcs_sdist_recur_list = prefetchable_pcs(burst_hists)
        
#        pref_pcs = pref_pcs_sdist_recur_list[0]

#        pc_sdist_hist = pref_pcs_sdist_recur_list[1]
        
#        pc_recur_hist = pref_pcs_sdist_recur_list[2]

#        remove_pcs = []

#        for pc in pref_pcs:
#            if not pc in global_prefetchable_pcs:
#                remove_pcs.append(pc)

#        for pc in remove_pcs:
#            pref_pcs.remove(pc)

#        pref_pcs = []

#        for (pc_rdist_hist, pc_stride_hist, pc_freq_hist, pc_time_hist) in burst_hists:
            
#            for pc in global_prefetchable_pcs:
#                if pc in pc_rdist_hist.keys():
#                    pref_pcs.append(pc)

#        rdist_hist_w_pf = rdist_hist_after_prefetching(burst_hists, pref_pcs)
    
#        win_mr_w_pf = lrumodel.miss_ratio_range([rdist_hist], cache_size_range, filtered_rdist_hist_list = [rdist_hist_w_pf])

#        cache_size_range = map(lambda x: x * conf.line_size, cache_size_range)

#        for cache_size in cache_size_range:
#            mr[cache_size] = mr.get(cache_size, 0) + win_mr._getitem__(cache_size)

#        for cache_size in cache_size_range:
#             mr_w_pf[cache_size] = mr_w_pf.get(cache_size, 0) + win_mr_w_pf._getitem__(cache_size)

#        win_count += 1


#    for (cache_size, miss_ratio) in mr.items():
#        mr[cache_size] = float(mr.get(cache_size, 0)) / float(win_count)

#    for (cache_size, miss_ratio) in mr_w_pf.items():
#        mr_w_pf[cache_size] = float(mr_w_pf.get(cache_size, 0)) / float(win_count)

#    mr_items = mr.items()
#    mr_items.sort(lambda (k0, v0), (k1, v1): cmp(k0, k1))

#    mr_w_pf_items = mr_w_pf.items()
#    mr_w_pf_items.sort(lambda (k0, v0), (k1, v1): cmp(k0, k1))

#    print "#cache size, fetch ratio, miss ratio (after prefetching)"

#    for (cache_size, miss_ratio) in mr_items:
#        print"%ld %lf %lf"%(cache_size, miss_ratio, mr_w_pf[cache_size])


if __name__ == "__main__":
    main()

