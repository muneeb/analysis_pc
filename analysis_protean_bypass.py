#!/usr/bin/python
import sys
import math
import os
import string
import gc

import operator

from optparse import OptionParser

from uart.hist import Hist
import uart.sample_filter as sample_filter

import pyusf
import lrumodel
import utils
import missratio

import redirect_analysis
import trace_analysis
import ins_trace_analysis

__version__ = "$Revision$"

class PrefParams:

    def __init__(self, delinq_load_addr, pf_type, pd, l1_mr, l2_mr, l3_mr):
        self.delinq_load_addr = delinq_load_addr
        self.pf_type = pf_type
        self.pd = pd
        self.l1_mr = l1_mr
        self.l2_mr = l2_mr
        self.l3_mr = l3_mr


class Conf:
    def __init__(self):
        parser = OptionParser("usage: %prog [OPTIONS...] INFILE")

        parser.add_option("-l", "--line-size",
                          type="int", default="64",
                          dest="line_size",
                          help="Use a specific line size.")

        parser.add_option("-t", "--type",
                          type="str", default="pfonly",
                          dest="analysis_type",
                          help="Analysis Type: 'pfonly', 'cons', 'aggr' ")

        parser.add_option("-m", "--mem",
                          type="float", default="3.2",
                          dest="cyc_per_mop",
                          help="Cycles per memory operation for this benchmark. ")

        parser.add_option("-n", "--num-samples",
                          type="int", default=None,
                          dest="num_samples",
                          help="Number of samples to be considered for analysis")

        parser.add_option("--mem-lat",
                          type="float", default="170",
                          dest="memory_latency",
                          help="Average Memory latency ")
        
        parser.add_option("--l1-lat",
                          type="float", default="2",
                          dest="l1_latency",
                          help="Average L1 cache latency ")

        parser.add_option("--l2-lat",
                          type="float", default="20",
                          dest="l2_latency",
                          help="Average L2 cache latency ")

        parser.add_option("--l3-lat",
                          type="float", default="45",
                          dest="l3_latency",
                          help="Average L3 cache latency ")

        parser.add_option("--l1-size",
                          type="int", default="64",
                          dest="l1_size",
                          help="L1 size in kilobytes (KB) ")        

        parser.add_option("--l2-size",
                          type="int", default="512",
                          dest="l2_size",
                          help="L2 size in kilobytes (KB) ")        

        parser.add_option("--l3-size",
                          type="int", default="6144",
                          dest="l3_size",
                          help="L3 size in kilobytes (KB) ")  
        
        parser.add_option("--detailed-modeling",
                          type="int", default="0",
                          dest="detailed_modeling",
                          help="Use detailed modeling")

        parser.add_option("--report-delinq-loads-only",
                          type="int", default="0",
                          dest="report_delinq_loads_only",
                          help="Use detailed modeling")

        parser.add_option("--all-delinq-loads",
                          type="int", default="0",
                          dest="all_delinq_loads",
                          help="print all delinquent loads ")

        parser.add_option("-p", "--path",
                          type="str", default=os.curdir,
                          dest="path",
                          help="Specify path for burst sample files")

        parser.add_option("-e",
                          type="str", default=None,
                          dest="exec_file",
                          help="Specify the executable to inspect")
        
        parser.add_option("-f", "--filter",
                          type="str", default="all()",
                          dest="filter",
                          help="Filter for events to display in histogram.")
                          
        parser.add_option("-o",
                          type="str", default="out.pref",
                          dest="outfile_pref",
                          help="Output file for prefetching decisions")
                          
        parser.add_option("--per-instr-mr-out",
                          type="str", default="out.perinsmr",
                          dest="outfile_perinsmr",
                          help="Output file for prefetching decisions")

        parser.add_option("--per-instr-nta-analysis",
                          type="int", default="0",
                          dest="per_instr_nta_analysis",
                          help="Generate per-instruction nta analysis")
                  
        parser.add_option("--nta-policy",
                            type="int", default="0",
                            dest="per_instr_nta_analysis",
                            help="Generate per-instruction nta analysis")

        parser.add_option("--help-nta-policy",
                          action="callback", callback=self.help_filters,
                          help="Display types of NTA policies available")

        parser.add_option("--stride-only-analysis",
                          type="int", default="0",
                          dest="stride_only",
                          help="only use stride information to generate prefetches")

#parser.add_option("--help-filters",
#                          action="callback", callback=self.help_filters,
#                          help="Display help about the filter language.")


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
        self.analysis_type = opts.analysis_type
        self.cyc_per_mop = opts.cyc_per_mop
        self.l3_latency = opts.l3_latency
        self.l2_latency = opts.l2_latency
        self.l1_latency = opts.l1_latency
        self.memory_latency = opts.memory_latency
        self.l3_size = opts.l3_size
        self.l2_size = opts.l2_size
        self.l1_size = opts.l1_size
        self.all_delinq_loads = opts.all_delinq_loads
        self.stride_only = opts.stride_only
        self.num_samples = opts.num_samples
        self.detailed_modeling = opts.detailed_modeling
        self.prefetch_decisions = {}
        self.exec_file = opts.exec_file
        self.report_delinq_loads_only = opts.report_delinq_loads_only
        self.per_instr_nta_analysis = opts.per_instr_nta_analysis
        self.outfile_pref = opts.outfile_pref
        self.outfile_perinsmr = opts.outfile_perinsmr

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

    for (pc_rdist_hist, pc_stride_hist, pc_freq_hist, pc_time_hist, pc_fwd_rdist_hist, pc_smptrace_hist) in burst_hists:
        
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

    for (pc_rdist_hist, pc_stride_hist, pc_freq_hist, pc_time_hist, pc_corr_hist, pc_fwd_rdist_hist, pc_smptrace_hist) in burst_hists:
        
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

    for (pc_rdist_hist, pc_stride_hist, pc_freq_hist, pc_time_hist, pc_corr_hist, pc_fwd_rdist_hist, pc_smptrace_hist) in burst_hists:
        
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
    pc_fwd_sdist_hist = {}

    for (pc_rdist_hist, pc_stride_hist, pc_freq_hist, pc_time_hist, pc_corr_hist, pc_fwd_rdist_hist, pc_smptrace_hist) in burst_hists:

        rdist_hist = rdist_hist_original(burst_hists)

        r2s = lrumodel.lru_sdist(rdist_hist)

        for (pc, rdist_hist) in pc_rdist_hist.items():

            if not pc in pc_sdist_hist:
                pc_sdist_hist[pc] = {}

            for (rdist, count) in rdist_hist.items():
                sd  = int(round(r2s[rdist]))
                pc_sdist_hist[pc][sd] = pc_sdist_hist[pc].get(sd, 0) + count

        for (pc, fwd_rdist_hist) in pc_fwd_rdist_hist.items():

            if not pc in pc_fwd_sdist_hist:
                pc_fwd_sdist_hist[pc] = {}

            for (rdist, count) in fwd_rdist_hist.items():
                sd  = int(round(r2s[rdist]))
                pc_fwd_sdist_hist[pc][sd] = pc_fwd_sdist_hist[pc].get(sd, 0) + count

        for (pc, time_hist) in pc_time_hist.items():

            if not pc in pc_recur_hist:
                pc_recur_hist[pc] = {}

            for (recur, count) in time_hist.items():

                if not recur in r2s:
                    recur_c = min(r2s.keys(), key=lambda k: abs(k - recur))
                    recur = recur_c

                sd  = int(round(r2s[recur]))
                pc_recur_hist[pc][sd] = pc_recur_hist[pc].get(sd, 0) + count

    return [pc_sdist_hist, pc_recur_hist, pc_fwd_sdist_hist]

def prefetchable_pcs(burst_hists, conf):

    sdist_recur_list = generate_per_pc_sdist_recurrence_hist(burst_hists)

    pc_sdist_hist = sdist_recur_list[0]

    pc_recur_hist = sdist_recur_list[1]

    pc_fwd_sdist_hist = sdist_recur_list[2]

    pref_pcs = []

    for (pc, sdist_hist) in pc_sdist_hist.items():
    
        if max(sdist_hist.keys()) > (float(conf.l1_size * 1024) / float(conf.line_size)):

            #in case of a dangling pointer, there "may" be no entry in pc_recur_hist 
            if pc in pc_recur_hist:
                max_recur = max(pc_recur_hist[pc].keys())

                if  max_recur < float(float(0.75) * float(conf.l1_size * 1024 / conf.line_size)):
                    pref_pcs.append(pc)
                else:
                    #need some clear strategy for nested loops, where outer loop's recurrence may be larger than L1 cache
                    total_recur_count = sum(pc_recur_hist[pc].itervalues()) 
                    max_recur_freq = float(float(pc_recur_hist[pc][max_recur])/float(total_recur_count) )

                    if max_recur_freq < 0.5:
                        pref_pcs.append(pc)
            else:
                pref_pcs.append(pc)


    return [pref_pcs, pc_sdist_hist, pc_recur_hist, pc_fwd_sdist_hist]

def build_global_prefetchable_pcs(global_prefetchable_pcs, pref_pcs):

    for pc in pref_pcs:
        if not pc in global_prefetchable_pcs:
            global_prefetchable_pcs.append(pc);

def build_global_pc_corr_hist(global_pc_corr_hist, pc_corr_hist):

    for (start_pc, corr_hist) in pc_corr_hist.items():
        if start_pc in global_pc_corr_hist:
            for (end_pc, count) in corr_hist.items():
                global_pc_corr_hist[start_pc][end_pc] = global_pc_corr_hist[start_pc].get(end_pc, 0) + count
        else:
            global_pc_corr_hist[start_pc] = {} 
            for (end_pc, count) in corr_hist.items():
                global_pc_corr_hist[start_pc][end_pc] = count


def build_global_pc_fwd_sdist_recur_hist(global_pc_fwd_sdist_hist, global_pc_recur_hist, pc_fwd_sdist_hist, pc_recur_hist, global_pc_sdist_hist, pc_sdist_hist):

    for (pc, fwd_sdist_hist) in pc_fwd_sdist_hist.items():
        if pc in global_pc_fwd_sdist_hist:
            for (sdist, count) in fwd_sdist_hist.items():
                global_pc_fwd_sdist_hist[pc][sdist] = global_pc_fwd_sdist_hist[pc].get(sdist, 0) + count
        else:
            global_pc_fwd_sdist_hist[pc] = {} 
            for (sdist, count) in fwd_sdist_hist.items():
                global_pc_fwd_sdist_hist[pc][sdist] = count

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


def build_global_pc_line_sdist_hist(global_pc_line_hist, global_line_sdist_hist, pc_line_hist, line_sdist_hist ):

    for (pc, line_hist) in pc_line_hist.items():
        if pc in global_pc_line_hist:
            for (line, count) in line_hist.items():
                global_pc_line_hist[pc][line] = global_pc_line_hist[pc].get(line, 0) + count
        else:
            global_pc_line_hist[pc] = {} 
            for (line, count) in line_hist.items():
                global_pc_line_hist[pc][line] = count

    for (line, sdist_hist) in line_sdist_hist.items():
        if line in global_line_sdist_hist:
            for (sdist, count) in sdist_hist.items():
                global_line_sdist_hist[line][sdist] = global_line_sdist_hist[line].get(sdist, 0) + count
        else:
            global_line_sdist_hist[line] = {} 
            for (sdist, count) in sdist_hist.items():
                global_line_sdist_hist[line][sdist] = count


def build_full_pc_stride_hist(burst_hists, full_pc_stride_hist):

    for (pc_rdist_hist, pc_stride_hist, pc_freq_hist, pc_time_hist, pc_corr_hist, pc_fwd_rdist_hist, pc_smptrace_hist) in burst_hists:
        
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

def is_nontemporal(pc, global_pc_corr_hist, global_pc_fwd_sdist_hist, conf):

    checked_pcs = []

    pending_pcs = [(pc, 1.0)]

    pc_arr_map = []

    for pc_prob_tup in pending_pcs:
        
        p_pc = pc_prob_tup[0]
        prob = float(pc_prob_tup[1])

        if p_pc in checked_pcs:
            continue

        if p_pc not in global_pc_corr_hist:
            continue

        total_count = sum(global_pc_corr_hist[p_pc].values())

        for end_pc in global_pc_corr_hist[p_pc].keys():
            
            if end_pc in checked_pcs:
                continue

            if end_pc not in pending_pcs:
                
                end_pc_prob = float(float(global_pc_corr_hist[p_pc][end_pc]) / float(total_count))

                arrival_prob = float( end_pc_prob * prob)
                
                if arrival_prob >= 0.4:
                    pending_pcs.append((end_pc, arrival_prob))

#            pc_arr_map.append((p_pc, end_pc, arrival_prob))

        sdist_list = global_pc_fwd_sdist_hist[p_pc].keys()
            
        non_l1_sdist_list = filter(lambda x: x > (float(conf.l1_size * 1024) / float(conf.line_size)), sdist_list)
        
        if len(non_l1_sdist_list) > 0 and min(non_l1_sdist_list) < (float(conf.l3_size * 1024 )/ float(conf.line_size)):
            return False
        
        checked_pcs.append(p_pc)

#    print >> sys.stderr, "data flow"
#    for tup in pc_arr_map:
#        print >> sys.stderr, tup
    
    return True

def per_instr_nontemporal_analysis(pc, global_pc_fwd_sdist_hist, outfile_perinsmr, conf):

    total_accesses = sum(global_pc_fwd_sdist_hist[pc].values())

    fwd_sdist_list = global_pc_fwd_sdist_hist[pc].items()
    
    l1_miss_fwd_sdist_list = filter(lambda (x,y): x > float(conf.l1_size * 1024 / conf.line_size), fwd_sdist_list)
    l2_miss_fwd_sdist_list = filter(lambda (x,y): x > float(conf.l2_size * 1024 / conf.line_size), fwd_sdist_list)
    l3_miss_fwd_sdist_list = filter(lambda (x,y): x > float(conf.l3_size * 1024 / conf.line_size), fwd_sdist_list)
    
    l1_fwd_misses = sum(map(lambda (x,y): y, l1_miss_fwd_sdist_list))
    
    l2_fwd_misses = sum(map(lambda (x,y): y, l2_miss_fwd_sdist_list))
    
    l3_fwd_misses = sum(map(lambda (x,y): y, l3_miss_fwd_sdist_list))
    
    l1_fwd_mr = float(float(l1_fwd_misses)/float(total_accesses))
    l2_fwd_mr = float(float(l2_fwd_misses)/float(total_accesses))
    l3_fwd_mr = float(float(l3_fwd_misses)/float(total_accesses))

#    l3_detailed_miss_dict = {}


    if l1_fwd_mr > 0.001:
        outfile_perinsmr.write("#Cache-size(KB), data stream future-miss-ratio\n")
        outfile_perinsmr.write("%d: %lf pc: 0x%lx\n"%(conf.l1_size,l1_fwd_mr, pc))
        outfile_perinsmr.write("%d: %lf\n"%(conf.l2_size,l2_fwd_mr))
        for l3_part in range(1024, conf.l3_size, 1024):
            l3part_miss_sdist_list = filter(lambda (x,y): x > float(l3_part * 1024 / conf.line_size), fwd_sdist_list)
            l3part_misses = sum(map(lambda (x,y): y, l3part_miss_sdist_list))
            l3part_mr = float(float(l3part_misses)/float(total_accesses))
        #   l3_detailed_miss_dict[l3_part] = l3part_mr
        
            outfile_perinsmr.write("%d: %lf\n"%(l3_part, l3part_mr))

        outfile_perinsmr.write("%d: %lf\n\n"%(conf.l3_size,l3_fwd_mr))




def generate_pref_pcs_info(global_prefetchable_pcs, global_pc_fwd_sdist_hist, global_pc_recur_hist, full_pc_stride_hist, global_pc_corr_hist, global_pc_sdist_hist, conf):

    outfile_pref = open(conf.outfile_pref, 'w')
    outfile_perinsmr =open(conf.outfile_perinsmr, 'w')

    cache_line_size = conf.line_size


    analysis_type = conf.analysis_type
    cyc_per_mop = conf.cyc_per_mop
    memory_latency = conf.memory_latency
    l3_latency = conf.l3_latency
    l2_latency = conf.l2_latency
    l1_latency = conf.l1_latency
    l3_size = conf.l3_size
    l2_size = conf.l2_size
    l1_size = conf.l1_size

    avg_mem_latency = memory_latency

    avg_iters = 0

    remove_pcs = []

    reduced_full_pc_stride_hist = reduce_stride_hist(full_pc_stride_hist)

    if conf.stride_only == 1:

        pref_pc_sd_hist = {}
        

        for pc in reduced_full_pc_stride_hist.keys():

            unrolled_loop_mop = 0

            sorted_x = sorted(reduced_full_pc_stride_hist[pc].iteritems(), key=operator.itemgetter(1), reverse=True)

            max_stride = sorted_x[0][0] 
            max_count = sorted_x[0][1]

            total_stride_count = sum(full_pc_stride_hist[pc].itervalues())

            max_stride_region_count = 0
            max_stride_region = math.floor(float(max_stride) / float(32))
                    
            for s,c in full_pc_stride_hist[pc].items():
            
                if math.floor(float(s) / float(32)) == max_stride_region:
                    max_stride_region_count += c

            if float(float(max_count) / float(total_stride_count)) < float(0.7):
                continue
            
            stride = max_stride

            sorted_x = sorted(global_pc_recur_hist[pc].iteritems(), key=operator.itemgetter(1), reverse=True)

            weight = 0
            avg_r = 0

            for r, c in sorted_x:
                avg_r += int(r) * int(c)
                weight += int(c)

            avg_r = round(float(avg_r)/ float(weight))

            if avg_r == 0:
                avg_r = 1

            recur_freq = sorted(global_pc_recur_hist[pc].values(), reverse=True) 
            recur_freq_thr = 200 #int(recur_freq[0])/6
            recur_freq_out_loop = filter(lambda y: y > recur_freq_thr, recur_freq)
            recur_freq_in_loop = filter(lambda y: y <= recur_freq_thr, recur_freq)

            loop_recur_freq = sum(recur_freq_in_loop)
            loop_reach_freq = sum(recur_freq_out_loop)

            if loop_reach_freq == 0:
                loop_reach_freq = 1
 
            avg_iters = float(float(loop_recur_freq)/float(loop_reach_freq))
                
            if avg_iters == 0:
                avg_iters = 1

            if abs(stride) < cache_line_size:
                    
                no_iters = int(round(float(cache_line_size) / float(abs(stride)) )) - 1

                if no_iters == 0:
                    no_iters = 1

                pd = math.ceil(float(avg_mem_latency) / float(avg_r * cyc_per_mop * no_iters ))
                    
                if pd == 0:
                    pd = 1 
                        
                if stride < 0:
                    pd = -1 * pd

                sd = cache_line_size * pd
                stride = cache_line_size
                
            else:
            
                no_iters = 1

                pd = math.ceil(float(avg_mem_latency) / float(avg_r * cyc_per_mop * no_iters))

                if pd == 0:
                    pd = 1 

                if stride < 0:
                    pd = -1 * pd

                sd = stride * pd
            
#           for pc_x in pref_pc_sd_hist.keys():
#                if abs(pc_x - pc) <= 50  and pref_pc_sd_hist[pc_x] == sd:
                    #loop unrolling possibility
#                    print >> sys.stderr, pc_x, pc, pref_pc_sd_hist[pc_x], sd
#                    unrolled_loop_mop = 1
#                    break

            pref_pc_sd_hist[pc] = sd

            if conf.detailed_modeling == 1:
                if (avg_iters/2) < pd:
                    pd = math.ceil(float(avg_iters)/float(2)) 
                    sd = stride * pd 

#            if unrolled_loop_mop == 0:
            print"%ld:pf:%d"%(pc, int(sd))

        return

    for pc in global_prefetchable_pcs:

        if not pc in reduced_full_pc_stride_hist.keys():
            continue

#        if not pc in global_pc_corr_hist.keys():
#            continue

        pf_type = 'pf'

        total_accesses = sum(global_pc_sdist_hist[pc].values())

#        non_l1_accesses = 0

        max_sdist = max(global_pc_sdist_hist[pc].keys())
        
        l1_misses = 0
        l2_misses = 0
        l3_misses = 0

        sdist_list = global_pc_sdist_hist[pc].items()

        l1_miss_sdist_list = filter(lambda (x,y): x > float(conf.l1_size * 1024 / conf.line_size), sdist_list)
        l2_miss_sdist_list = filter(lambda (x,y): x > float(conf.l2_size * 1024 / conf.line_size), sdist_list)
        l3_miss_sdist_list = filter(lambda (x,y): x > float(conf.l3_size * 1024 / conf.line_size), sdist_list)

        l1_misses = sum(map(lambda (x,y): y, l1_miss_sdist_list))

        l2_misses = sum(map(lambda (x,y): y, l2_miss_sdist_list))

        l3_misses = sum(map(lambda (x,y): y, l3_miss_sdist_list))

        ref_count = sum(map(lambda (x,y): y, sdist_list))

        l1_mr = float(float(l1_misses)/float(total_accesses)) 
        l2_mr = float(float(l2_misses)/float(total_accesses)) 
        l3_mr = float(float(l3_misses)/float(total_accesses))

        if conf.per_instr_nta_analysis == 1:
            per_instr_nontemporal_analysis(pc, global_pc_fwd_sdist_hist, outfile_perinsmr, conf)


        if conf.detailed_modeling == 1:
            
            cb_score = float(1)/float(avg_mem_latency)
            if l1_mr < cb_score and l3_mr < 0.005:
                print >> sys.stderr, "\ncb-ignored pc-hex:%lx   pc:%ld" % (pc, pc)
                print >> sys.stderr, "L1 MR %lf%%, L2 MR %lf%%, L3_MR %lf%%, -- %s: dataset size: %lf MB"%(l1_mr, l2_mr, l3_mr, hex(pc), float(max_sdist * conf.line_size / (1024*1024)))
                continue

            if l1_mr >= cb_score and conf.report_delinq_loads_only == 1:
                print pc, l1_mr

            if conf.report_delinq_loads_only == 1:
                continue
            

        if analysis_type == "aggr" and pc in global_pc_fwd_sdist_hist.keys():

            sdist_list = global_pc_fwd_sdist_hist[pc].keys()

            non_l1_sdist_list = filter(lambda x: x > float(conf.l1_size * 1024 / conf.line_size), sdist_list)

            if len(non_l1_sdist_list) == 0 or min(non_l1_sdist_list) > (conf.l3_size * 1024 / conf.line_size):
                pf_type = 'nta'
                isnontemporal = True
        
        if analysis_type == "cons":
            isnontemporal = False
            isnontemporal = is_nontemporal(pc, global_pc_corr_hist, global_pc_fwd_sdist_hist, conf)
            if isnontemporal:
                pf_type = 'nta'


        sorted_x = sorted(reduced_full_pc_stride_hist[pc].iteritems(), key=operator.itemgetter(1), reverse=True)

        max_stride = sorted_x[0][0] 
        max_count = sorted_x[0][1]

        total_stride_count = sum(full_pc_stride_hist[pc].itervalues())

        max_stride_region_count = 0
        max_stride_region = math.floor(float(max_stride) / float(cache_line_size))
                    
        for s,c in full_pc_stride_hist[pc].items():
            
            if math.floor(float(s) / float(cache_line_size)) == max_stride_region:
                max_stride_region_count += c

        print >> sys.stderr,"\n\n"
        print >> sys.stderr,"Stride %lu"%(pc)
        
        max_stride_region_freq = float(float(max_stride_region_count) / float(total_stride_count))

        if max_stride_region_freq < float(0.7):
            remove_pcs.append(pc)

            if conf.all_delinq_loads and isnontemporal:
                print"0x%lx:%s:%d"%(pc, pf_type, 0)

            continue
 

        print >> sys.stderr, "regular strided load (L1 MR %lf%%, L2 MR %lf%%, L3_MR %lf%%, max stride region ratio %lf -- %s): dataset size: %lf MB"%(l1_mr, l2_mr, l3_mr, 
                    float(float(max_stride_region_count) / float(total_stride_count)), hex(pc),  float(max_sdist * conf.line_size / (1024*1024)) )
        

        min_r = min(global_pc_recur_hist[pc].keys())

        stride = max_stride

        if (abs(stride) * max_count) <= cache_line_size:
            continue

        
#        if max(global_pc_sdist_hist[pc].keys()) > (l3_size * 1024 / cache_line_size):
        avg_mem_latency = memory_latency 
#        elif max(global_pc_sdist_hist[pc].keys()) > (l2_size * 1024 / cache_line_size) and max(global_pc_sdist_hist[pc].keys()) < (l3_size * 1024 / cache_line_size):
#            avg_mem_latency = l3_latency 
#        elif max(global_pc_sdist_hist[pc].keys()) > (l2_size * 1024 / cache_line_size) and max(global_pc_sdist_hist[pc].keys()) < (l2_size * 1024 / cache_line_size):
#            avg_mem_latency = l2_latency

        total_count = sum(global_pc_fwd_sdist_hist[pc].values())

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
            

        recur_freq = sorted(global_pc_recur_hist[pc].values(), reverse=True) 
        recur_freq_thr = 200 #int(recur_freq[0])/6
        recur_freq_out_loop = filter(lambda y: y > recur_freq_thr, recur_freq)
        recur_freq_in_loop = filter(lambda y: y <= recur_freq_thr, recur_freq)

        loop_recur_freq = sum(recur_freq_in_loop)
        loop_reach_freq = sum(recur_freq_out_loop)

        if loop_reach_freq == 0:
            loop_reach_freq = 1
 
        avg_iters = float(float(loop_recur_freq)/float(loop_reach_freq))

        if avg_iters == 0:
            avg_iters = 1

        if abs(stride) < cache_line_size:

            no_iters = int(round(float(cache_line_size) / float(abs(stride)) )) - 1

            if no_iters == 0:
                no_iters = 1

            pd = math.ceil(float(avg_mem_latency) / float(avg_r * cyc_per_mop * no_iters ))

            if pd == 0:
                pd = 1 

            if stride < 0:
                pd = -1 * pd

            stride = cache_line_size

            sd = cache_line_size * pd

#############################################################

#            if full_pc_stride_hist[pc][stride] < pd:
#            if (avg_iters/2) < pd:
#                pd = math.ceil(float(avg_iters)/float(2))
#                sd = cache_line_size * pd #2

#############################################################

        else:
            
            no_iters = 1

            pd = math.ceil(float(avg_mem_latency) / float(avg_r * cyc_per_mop * no_iters))

            if pd == 0:
                pd = 1 

            if stride < 0:
                pd = -1 * pd

            sd = stride * pd

#############################################################

#            if full_pc_stride_hist[pc][stride] < pd:
        if conf.detailed_modeling == 1:
            if (avg_iters/2) < pd:
                pd = math.ceil(float(avg_iters)/float(2)) 
                sd = stride * pd 
            
#############################################################

        print >> sys.stderr, pc
        print >> sys.stderr, total_count
        print >> sys.stderr, stride, pd, sd, avg_iters
        print >> sys.stderr, "\n\n"
#        print >> sys.stderr, recur_freq

#        print >> sys.stderr, "\n\n\n"
                
#        print >> sys.stderr, full_pc_stride_hist[pc]

#        if conf.detailed_modeling == 1:

#            if isnontemporal and ((pd * 2) < (avg_iters / 2)):
#                sd = sd * 2
#                print >> sys.stderr, "stride doubled for non temporal access (load from DRAM)"
    
        #add prefetch decision to central data structure
        pref_param = PrefParams(pc, pf_type, pd, l1_mr, l2_mr, l3_mr)
        conf.prefetch_decisions[pc] = pref_param
        
#        if total_count > 50:
        outfile_pref.write("0x%lx:%s:%d\n"%(pc, pf_type, int(sd)))
            #        print"0x%lx:%s:%d"%(pc, pf_type, int(sd))

    outfile_pref.close()
    outfile_perinsmr.close()
        
        

def main():
    conf = Conf()

    listing = os.listdir(conf.path)

    cache_size_range = default_range_func()

    win_count = 0

    mr = {}

    mr_w_pf = {}

    pref_pcs_win = {}

    full_pc_stride_hist = {}

    global_pc_fwd_sdist_hist = {}

    global_pc_sdist_hist = {}

    global_pc_corr_hist = {}

    global_pc_recur_hist = {}
    
    global_prefetchable_pcs = []
    
    global_pc_smptrace_hist = {}

    if not conf.num_samples is None:

        num_sample_files = len(listing)

        files_required = math.ceil(float(conf.num_samples) / float(1200)) + 1 # 1200 is the number of samples per file

        files_sapcing = int(math.ceil(float(num_sample_files) / float(files_required)))

        print >> sys.stderr, "files spacing: %d"%(files_sapcing)

        if files_sapcing == 0:
            files_sapcing = 1

        file_no = 0

        listing = []
        
        while file_no < num_sample_files:
            file_name = "sample."+str(file_no)
            listing.append(file_name)
            file_no += files_sapcing

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


        pref_pcs_sdist_recur_list = prefetchable_pcs(burst_hists, conf)
        
        pref_pcs = pref_pcs_sdist_recur_list[0]
        
        pc_sdist_hist = pref_pcs_sdist_recur_list[1]
        
        pc_recur_hist = pref_pcs_sdist_recur_list[2]
            
        pc_fwd_sdist_hist = pref_pcs_sdist_recur_list[3]
        
        build_global_prefetchable_pcs(global_prefetchable_pcs, pref_pcs)
        
        pc_corr_hist = burst_hists[0][4]

        build_global_pc_corr_hist(global_pc_corr_hist, pc_corr_hist)

        build_global_pc_fwd_sdist_recur_hist(global_pc_fwd_sdist_hist, global_pc_recur_hist, pc_fwd_sdist_hist, pc_recur_hist, global_pc_sdist_hist, pc_sdist_hist)
    
        build_full_pc_stride_hist(burst_hists, full_pc_stride_hist)

        pc_smptrace_hist = burst_hists[0][6]

        ins_trace_analysis.add_trace_to_global_pc_smptrace_hist(global_pc_smptrace_hist, pc_smptrace_hist)


    generate_pref_pcs_info(global_prefetchable_pcs, global_pc_fwd_sdist_hist, global_pc_recur_hist, full_pc_stride_hist, global_pc_corr_hist, global_pc_sdist_hist, conf)

#    full_pc_stride_hist.clear()

    global_pc_fwd_sdist_hist.clear()

    global_pc_sdist_hist.clear()

    global_pc_corr_hist.clear()

    global_pc_recur_hist.clear()
    
    gc.collect()

    for pc in conf.prefetch_decisions.keys():
        pref_param = conf.prefetch_decisions[pc]
        print >> sys.stderr, "pc: %lx"%(pc)
        print >> sys.stderr, "pf_type "+pref_param.pf_type

#    redirect_analysis.analyze_non_strided_delinq_loads(global_pc_smptrace_hist, full_pc_stride_hist, conf.prefetch_decisions, conf.exec_file, conf.num_samples, conf.memory_latency)


if __name__ == "__main__":
    main()

