#!/usr/bin/python

import string
import sys
import re
import operator

from optparse import OptionParser

class Conf:
    def __init__(self):
        parser = OptionParser("usage: %prog [OPTIONS...] INFILE")

        parser.add_option("-f", "--delinq-loads-file",
                          type="str", default=None,
                          dest="delinq_loads_file",
                          help="Specify path for burst sample files")

        parser.add_option("-r", "--ref2",
                          type="str", default=None,
                          dest="ref2",
                          help="Another reference file (for another input)")

        (opts, args) = parser.parse_args()

        self.ref2 = opts.ref2
        
        if len(args) == 0:
            print >> sys.stderr, "No input file specified."
            sys.exit(1)

        self.delinq_loads_file = opts.delinq_loads_file

        self.re_hex_address = re.compile("0[xX][0-9a-fA-F]+|[\s]+\d+")
        self.ref_stats_file = args[0]

def read_load_hit_miss_stats(conf, ref_stats_file):

    pc_miss_hist = {}
    pc_hit_hist = {}

    acc_misses = 0
    acc_accesses = 0

    try:
        infile = open(ref_stats_file, "r")

        for line in infile:
            if line.find("Total-Hits") != -1:
                line_tokens = line.split()
                total_hits = long(line_tokens[2])
                
            if line.find("Total-Misses") != -1:
                line_tokens = line.split()
                total_misses = long(line_tokens[2])

            if line.find("Total-Accesses") != -1:
                line_tokens = line.split()
                total_accesses = long(line_tokens[2])
                break 

        for line in infile:
            line_tokens = conf.re_hex_address.findall(line)
            if not line_tokens or len(line_tokens) < 3:
                continue
            hex_pc = line_tokens[0]
            dec_pc = int(hex_pc, 16)
            miss_count = long(line_tokens[1])
            hit_count = long(line_tokens[2])
            pc_miss_hist[dec_pc] = miss_count
            pc_hit_hist[dec_pc] = hit_count

            acc_misses += miss_count
            acc_accesses += hit_count
            acc_accesses += miss_count

#        if acc_misses < (0.9 * float(total_misses)):
#            print >> sys.stderr, "accumulated misses dont equal total misses"
#            total_misses = acc_misses
#            total_accesses = acc_accesses    

        if acc_accesses != total_accesses:
            acc_access_err = float(total_accesses - acc_accesses) / float(total_accesses) * 100
            acc_miss_err = float(total_misses - acc_misses) / float(total_misses) * 100
            print "acc err: %lf miss err: %lf" % (acc_access_err, acc_miss_err)
            print >> sys.stderr, "accumulated misses dont equal total misses"
            total_accesses = acc_accesses
            total_misses = acc_misses

        return [pc_miss_hist, pc_hit_hist, total_misses, total_accesses]

    except IOError, e:
        raise IOError('Can not read input file')

def read_delinq_pcs(conf):

    delinq_load_pcs=[]
    
    try:
        infile = open(conf.delinq_loads_file, "r")

        for line in infile:
            line_tokens = line.split(':')
            try:
                dec_pc = long(line_tokens[0])
            except ValueError, e:
                dec_pc = long(line_tokens[0], 16)
            delinq_load_pcs.append(dec_pc)

    except IOError, e:
        raise IOError('Can not read file specifying delinquent loads')

    return delinq_load_pcs

def sort_leading_deinquent_loads(load_hit_miss_list):
    
    pc_miss_hist = load_hit_miss_list[0]
    pc_hit_hist = load_hit_miss_list[1]
    total_misses = load_hit_miss_list[2]
    total_accesses = load_hit_miss_list[3]
    pc_mr_hist = {}
   
    miss_ratio = round(float(total_misses)/float(total_accesses) * 100, 3)

    thr_miss_ratio = float(1.0 * float(miss_ratio)) 
    
    sorted_x = sorted(pc_miss_hist.iteritems(), key=operator.itemgetter(1), reverse=True)

    mr = 0
    acc_miss_ratio = 0
    for pc, misses in sorted_x:
        pc_miss_ratio = round(float(misses)/float(total_accesses) * 100, 3)
        pc_mr = round(float(misses)/float(misses+pc_hit_hist[pc]) * 100, 3)
        acc_miss_ratio += pc_miss_ratio

        if float(acc_miss_ratio > thr_miss_ratio) or pc_miss_ratio == 0:
            mr += pc_miss_ratio
            pc_mr_hist[pc] = pc_miss_ratio
            break

        mr += pc_miss_ratio
        pc_mr_hist[pc] = pc_miss_ratio

    print "miss-ratio: %.2lf%%"%(miss_ratio)
    print "#delinqent loads: %d"%(len(pc_mr_hist.keys()))

    #pc_mr_hist {pc: miss_ratio}
    return pc_mr_hist

def compute_delinq_load_overlap(pc_mr_hist, pc_mr_hist2):

    overlap_count = 0
    for pc in pc_mr_hist2.keys():
        if pc in pc_mr_hist.keys():
            overlap_count += 1
            
    dload_overlap = round(float(overlap_count)/float(len(pc_mr_hist2)), 4)

    return dload_overlap
            

def compute_delinq_load_identification_coverage(pc_mr_hist, delinq_load_pcs, pc_miss_hist, pc_hit_hist, total_misses):

    total_mr = sum(pc_mr_hist.itervalues())

    cov_mr = 0
    
    cov_misses = 0

#    for dec_pc in delinq_load_pcs:
#        if dec_pc in pc_mr_hist.keys():
#            cov_mr += pc_mr_hist[dec_pc]

    for pc in delinq_load_pcs:
        if pc in pc_mr_hist.keys() and pc in pc_miss_hist:
            cov_misses = cov_misses + pc_miss_hist[pc]
            
    coverage = round(float(cov_misses)/float(total_misses), 5)

#    coverage = round(float(cov_mr/total_mr), 5)

#    c = len(pc_mr_hist.keys())
#    p = len(delinq_load_pcs)
#    pnc=0
#    pmc=0
#    for pc in delinq_load_pcs:
#        if pc in pc_mr_hist.keys():
#            pnc += 1
#        else:
#            pmc += 1

    c = 0
    p = 0
    pnc = 0
    pmc = 0

    # count all the accesses of the top 90% delinquent memory accesses 
    for pc in pc_mr_hist.keys():
        c = c + pc_miss_hist[pc] + pc_hit_hist[pc]
        
    # count all the accesses of our identified delinquent loads
    for pc in delinq_load_pcs:
        if pc in pc_miss_hist:
            p = p + pc_miss_hist[pc] + pc_hit_hist[pc]
#        else:
#            print >> sys.stderr, "skipped"
    print "%lx"%(pc)
    for pc in delinq_load_pcs:
        if pc in pc_mr_hist.keys():
            pnc = pnc + pc_miss_hist[pc] + pc_hit_hist[pc]
        elif pc in pc_miss_hist:
            pmc = pmc + pc_miss_hist[pc] + pc_hit_hist[pc]

    recall = round(float(pnc)/float(c), 5)
    false_positives = round(float(pmc)/float(p), 5)

    return [coverage, recall, false_positives]

def compute_overall_coverage(delinq_load_pcs, pc_miss_hist, total_misses):

    miss_count = 0

    for pc in delinq_load_pcs:
        if pc in pc_miss_hist:
            miss_count += pc_miss_hist[pc]

    ov_coverage = round(float(miss_count)/float(total_misses), 5)

    return ov_coverage

def compute_pref_to_removed_misses_ratio(delinq_load_pcs, pc_miss_hist, pc_hit_hist):

    misses_removed = 0
    pref_executed = 0

    for pc in delinq_load_pcs:
        if pc in pc_miss_hist:
            misses_removed += pc_miss_hist[pc]
            pref_executed += pc_miss_hist[pc]
            pref_executed += pc_hit_hist[pc]

    pref_to_misses_removed = round(float(pref_executed)/float(misses_removed), 5)
    
    return pref_to_misses_removed 

def main():

    conf = Conf()

    try:
        load_hit_miss_list = read_load_hit_miss_stats(conf, conf.ref_stats_file)
        
    except IOError, e:
            sys.exit(1)

    pc_mr_hist = sort_leading_deinquent_loads(load_hit_miss_list)

    if conf.ref2 == None:
        try:         
            pc_miss_hist = load_hit_miss_list[0]
            pc_hit_hist = load_hit_miss_list[1]
            total_misses = load_hit_miss_list[2]
            total_accesses = load_hit_miss_list[3]

            delinq_load_pcs = read_delinq_pcs(conf)

            crf_list = compute_delinq_load_identification_coverage(pc_mr_hist, delinq_load_pcs, pc_miss_hist, pc_hit_hist, total_misses)
            coverage = crf_list[0]
            recall = crf_list[1]
            false_positives = crf_list[2]

            ov_coverage = compute_overall_coverage(delinq_load_pcs, pc_miss_hist, total_misses)

            pref_to_misses_removed = compute_pref_to_removed_misses_ratio(delinq_load_pcs, pc_miss_hist, pc_hit_hist)
        
        except IOError, e:
            sys.exit(1)

        print "coverage: %.2lf%%"%(coverage * 100)
        print "recall: %.2lf%%"%(recall * 100)
        print "false positives: %.2lf%%"%(false_positives * 100)
        print "overall cov.: %.2lf%%"%(ov_coverage * 100)
        print "prefetches excuted to remove 1 L1$ miss: %.2lf"%(pref_to_misses_removed)

    else:
        try:
            load_hit_miss_list2 = read_load_hit_miss_stats(conf, conf.ref2)

        except IOError, e:
            sys.exit(1)

        pc_mr_hist2 = sort_leading_deinquent_loads(load_hit_miss_list2)

        dload_overlap = compute_delinq_load_overlap(pc_mr_hist, pc_mr_hist2)

        print "overlap: %.2lf%%"%(dload_overlap * 100)

if __name__ == "__main__":
    main()
