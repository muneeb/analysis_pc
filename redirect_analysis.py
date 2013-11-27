#!/usr/bin/python

import string
import sys
import re
import operator
import os
import pyusf
import utils
import math

from uart.hist import Hist
import uart.sample_filter as sample_filter

from optparse import OptionParser
import subprocess
import trace_analysis
import static_BB_cfg
import ins_trace_analysis
import ins_trace_ptr_nobj_analysis
import disassm


class PtrPrefParams:

    def __init__(self, schedule_addr, pf_type, clobber_reg, base_reg, mem_dis, freq_update_pc, updated_reg, score, fwd_score, freq_delinq_loads_till_use, freq_delinq_loads_till_update):
        
        self.schedule_addr = schedule_addr
        self.pf_type = pf_type
        self.clobber_reg = clobber_reg
        self.base_reg = base_reg
        self.mem_dis = mem_dis
        self.freq_update_pc = freq_update_pc
        self.updated_reg = updated_reg
        self.score = score
        self.fwd_score = fwd_score
        self.freq_delinq_loads_till_use = freq_delinq_loads_till_use
        self.freq_delinq_loads_till_update = freq_delinq_loads_till_update
        self.is_useful = True
        
class Conf1:

    def __init__(self, exec_file, all_delinq_loads_list, num_samples, avg_mem_latency):
        self.exec_file = exec_file

        self.re_hex_address = re.compile("0[xX][0-9a-fA-F]+")

        self.line_size = 64
        self.BB_reg_prefetch_dict = {}
        self.indirect_pref_decisions = {}
        self.all_delinq_loads_list = all_delinq_loads_list
        self.resolved_count = 0
        self.num_samples = num_samples
        self.avg_mem_latency = avg_mem_latency

class Conf:
    def __init__(self):
        parser = OptionParser("usage: %prog [OPTIONS...] INFILE")

        parser.add_option("-l",
                          type="str", default=None,
                          dest="addr_file",
                          help="Specify the list containing addresses of delinqeunt loads")

        parser.add_option("-a",
                          type="str", default=None,
                          dest="dec_address",
                          help="Specify the address of delinqeunt load (in decimal)")

        parser.add_option("-x",
                          type="str", default=None,
                          dest="hex_address",
                          help="Specify the address of delinquent load (hex without 0x)")

        parser.add_option("-e",
                          type="str", default=None,
                          dest="exec_file",
                          help="Specify the executable to inspect")

        parser.add_option("-p", "--path",
                          type="str", default=os.curdir,
                          dest="path",
                          help="Specify path for burst sample files")

        parser.add_option("-n", "--num-samples",
                          type="int", default=None,
                          dest="num_samples",
                          help="Number of samples to be considered for analysis")

        parser.add_option("--pref-dec",
                          type="str", default=None,
                          dest="pref_dec",
                          help="Give the prefetch decision as string")

        parser.add_option("-f", "--filter",
                          type="str", default="all()",
                          dest="filter",
                          help="Filter for events to display in histogram.")

        (opts, args) = parser.parse_args()

        self.dec_address = opts.dec_address

        self.hex_address = opts.hex_address
        self.exec_file = opts.exec_file

        self.re_hex_address = re.compile("0[xX][0-9a-fA-F]+")

        self.path = opts.path
        self.line_size = 64
        self.filter = opts.filter
        self.addr_file = opts.addr_file
        self.BB_reg_prefetch_dict = {}
        self.indirect_pref_decisions = {}
        self.all_delinq_loads_list = []
        self.resolved_count = 0
        self.pref_dec = opts.pref_dec
        self.num_samples = opts.num_samples


def get_delinq_load_address_list(conf):

    delinq_load_address_list = []

    if conf.addr_file == None:
        return

    try:
        f = open(conf.addr_file)
        lines = f.readlines()
        f.close()
    except IOError, e:
        print >> sys.stderr, "Error: %s" % str(e)
        return None

    for line in lines:
        line_tokens = line.split(":")
        if("ptr" in line_tokens[1]):
            delinq_load_address_list.append(int(line_tokens[0]))
            conf.all_delinq_loads_list.append(int(line_tokens[0]))

    print "delinq addresses: %lu" % (len(delinq_load_address_list))

    delinq_load_address_list = sorted(delinq_load_address_list)

    return delinq_load_address_list 


def open_sample_file(file_name, line_size=64):
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


def available_vol_regs(ins_src_regs_dict, ins_dst_regs_dict):

    vol_regs_list = [23, 22, 21, 20, 19, 18, 17]

    for instr_addr in ins_src_regs_dict.keys():

        rregs_list = ins_src_regs_dict[instr_addr]
        
#        if instr_addr in ins_dst_regs_dict:
#            rregs_list += ins_dst_regs_dict[instr_addr]

        for reg in rregs_list:
            
            if reg in vol_regs_list:
                vol_regs_list.remove(reg)

    return vol_regs_list 


def check_dominant_direction(update_pc_weights, cfg):

    acc_freq = 0
    base_reg_dis_dict = {}
    pc_base_reg_dis_dict = {}

    for pc_freq_tup in update_pc_weights:
        pc = pc_freq_tup[0]
        freq = pc_freq_tup[1]
        
        if not pc in cfg.ins_base_reg_dict:
            continue

        base_reg_id = cfg.ins_base_reg_dict[pc]
        mem_dis = cfg.ins_mem_dis_dict[pc]

        id_tup = (base_reg_id, mem_dis)

        if not id_tup in base_reg_dis_dict:
            base_reg_dis_dict[id_tup] = freq
        else:
            base_reg_dis_dict[id_tup] += freq

        if not id_tup in pc_base_reg_dis_dict:
            pc_base_reg_dis_dict[id_tup] = pc

    for id_tup in base_reg_dis_dict.keys():
        if base_reg_dis_dict[id_tup] >= 0.5:
            return pc_base_reg_dis_dict[id_tup]

    return None

#check if a prefetch has been inserted in a BB for a given base register. If Yes, then no need to insert more prefetches
def add_to_BB_indirect_pref_decisions(delinq_load_addr, schedule_addr, cfg, conf):

    BB_addr = static_BB_cfg.discover_BB_for_address(schedule_addr, cfg.BB_dict)
    base_reg_id = cfg.ins_base_reg_dict[delinq_load_addr]
    mem_dis = cfg.ins_mem_dis_dict[delinq_load_addr]

    if BB_addr in conf.BB_reg_prefetch_dict:
        if base_reg_id in conf.BB_reg_prefetch_dict[BB_addr]:
            conf.BB_reg_prefetch_dict[BB_addr][base_reg_id] += [(schedule_addr, mem_dis, delinq_load_addr)]
        else:
            conf.BB_reg_prefetch_dict[BB_addr][base_reg_id] = [(schedule_addr, mem_dis, delinq_load_addr)]
    else:
        conf.BB_reg_prefetch_dict[BB_addr] = {}
        conf.BB_reg_prefetch_dict[BB_addr][base_reg_id] = [(schedule_addr, mem_dis, delinq_load_addr)]


def BB_prefetch_status(delinq_load_addr, cfg, conf):

    pf_type = "ptr"

    BB_addr = static_BB_cfg.discover_BB_for_address(delinq_load_addr, cfg.BB_dict)
    base_reg_id = cfg.ins_base_reg_dict[delinq_load_addr]

    if BB_addr in conf.BB_reg_prefetch_dict:
        if base_reg_id in conf.BB_reg_prefetch_dict[BB_addr]:

            mem_dis_list = map(lambda x: x[1], conf.BB_reg_prefetch_dict[BB_addr][base_reg_id])

            mem_dis = cfg.ins_mem_dis_dict[delinq_load_addr]
            max_dis = max(mem_dis_list)
            mem_dis_diff = max_dis - mem_dis

            if mem_dis_diff == 0:
                return pf_type
            elif mem_dis_diff < conf.line_size:
                pf_type = "ptradj"
            else:
                pf_type = "ptradj2"

    return pf_type

#checks for nested objects - Not schedulable if "nested object"
def is_reschedulable(delinq_load_addr, update_addr, cfg):

    base_reg_id_delinq_load = cfg.ins_base_reg_dict[delinq_load_addr]
    base_reg_id_update_instr = cfg.ins_base_reg_dict[update_addr]

    if base_reg_id_delinq_load == base_reg_id_update_instr:
        return True
    
    return False

def are_equal(delinq_load_addr, update_addr, cfg):
    
    if delinq_load_addr == update_addr:
        return True

    base_reg_id_delinq_load = cfg.ins_base_reg_dict[delinq_load_addr]
    base_reg_id_update_instr = cfg.ins_base_reg_dict[update_addr]
    
    mem_dis_delinq_load = cfg.ins_mem_dis_dict[delinq_load_addr]
    mem_dis_update_instr = cfg.ins_mem_dis_dict[update_addr]

    if base_reg_id_delinq_load == base_reg_id_update_instr and \
           mem_dis_delinq_load == mem_dis_update_instr:
        return True

    return False

def do_cost_benefit_analysis(cfg, conf, delinq_load_addr, prefetch_decisions):


    for addr in [delinq_load_addr]: #conf.indirect_pref_decisions.keys():
        
        is_useless = False

#        if prefetch_decisions[addr].l3_mr < 0.007:
#            if prefetch_decisions[addr].l2_mr < 0.04:
#                if prefetch_decisions[addr].l1_mr < 0.15:
        cb_score = float(5)/float(conf.avg_mem_latency)
        if prefetch_decisions[addr].l1_mr < cb_score and prefetch_decisions[addr].l3_mr < 0.005:
            conf.indirect_pref_decisions[addr].is_useful = False

            print >> sys.stderr, "irr-cb-ignored: %lx"%(delinq_load_addr)
            continue
        
        spec_resched = True
        if conf.indirect_pref_decisions[addr].clobber_reg == "None":
            spec_resched = False

        ins_count_till_update = conf.indirect_pref_decisions[addr].fwd_score
        delinq_loads_till_update = conf.indirect_pref_decisions[addr].freq_delinq_loads_till_update

        ins_count_till_use = conf.indirect_pref_decisions[addr].score
        delinq_loads_till_use = conf.indirect_pref_decisions[addr].freq_delinq_loads_till_use

        if spec_resched:
            
            if ins_count_till_use < 2:
                spec_resched = False

            if ins_count_till_update  < 12:
                if delinq_loads_till_update < 2:
                    conf.indirect_pref_decisions[addr].clobber_reg = "None"
                    conf.indirect_pref_decisions[addr].schedule_addr = conf.indirect_pref_decisions[addr].freq_update_pc
                    spec_resched = False

        if not spec_resched:
            if ins_count_till_use < 7 and delinq_loads_till_use < 2:
                is_useless = True
            elif ins_count_till_use < 11 and delinq_loads_till_use < 1:
                is_useless = True

        
        if is_useless:
            conf.indirect_pref_decisions[addr].is_useful = False
            continue
            
        sched_addr = conf.indirect_pref_decisions[addr].schedule_addr

        add_to_BB_indirect_pref_decisions(addr, sched_addr, cfg, conf)
        


def decide_prefetch_schedules(cfg, conf):


    BB_addr_list = sorted(conf.BB_reg_prefetch_dict.keys())

    for BB_addr in BB_addr_list:
        for base_reg_id in conf.BB_reg_prefetch_dict[BB_addr].keys():

            addr_list = map(lambda x: x[0], conf.BB_reg_prefetch_dict[BB_addr][base_reg_id])
            mem_dis_list = map(lambda x: x[1], conf.BB_reg_prefetch_dict[BB_addr][base_reg_id])
            delinq_load_addr_list = map(lambda x: x[2], conf.BB_reg_prefetch_dict[BB_addr][base_reg_id])
            delinq_load_addr_list = filter(lambda x: x not in delinq_load_addr_list, delinq_load_addr_list)
            max_dis = max(mem_dis_list)
            min_dis = min(mem_dis_list)

            mem_dis_diff = max_dis - min_dis

            if mem_dis_diff == 0 and min_dis < conf.line_size:
                pf_type = "ptr"
            elif min_dis >= conf.line_size and mem_dis_diff < conf.line_size:
                pf_type = "ptradjonly"
            elif mem_dis_diff <= conf.line_size:
                pf_type = "ptradj"
            else:
                pf_type = "ptradj2"

            #schedule earliest
            schedule_addr = min(addr_list)

            nta_str=""
            for addr in delinq_load_addr_list:
                if "nta" in conf.indirect_pref_decisions[addr].pf_type:
                    nta_str="nta"
                else:
                    nta_str=""
                    break

            print >> sys.stderr, "--schedule %ul--"%(schedule_addr)
            print >> sys.stderr, "--address list--"
            print >> sys.stderr, addr_list
            print >> sys.stderr, "--mem dis list--"
            print >> sys.stderr, mem_dis_list
            

            for addr in delinq_load_addr_list:
                if conf.indirect_pref_decisions[addr].schedule_addr == schedule_addr:
                    conf.indirect_pref_decisions[addr].pf_type = pf_type + nta_str
                    continue

                conf.indirect_pref_decisions[addr].is_useful = False


def print_indirect_prefetch_decisions(conf):
    
    for addr in conf.indirect_pref_decisions.keys():
        
        if conf.indirect_pref_decisions[addr].is_useful:

            print"0x%lx:%s:%s:%s:%d:0x%lx:%s:%d"%(conf.indirect_pref_decisions[addr].schedule_addr, 
                                                      conf.indirect_pref_decisions[addr].pf_type, 
                                                      conf.indirect_pref_decisions[addr].clobber_reg, 
                                                      conf.indirect_pref_decisions[addr].base_reg, 
                                                      conf.indirect_pref_decisions[addr].mem_dis, 
                                                      conf.indirect_pref_decisions[addr].freq_update_pc, 
                                                      conf.indirect_pref_decisions[addr].updated_reg, 
                                                      conf.indirect_pref_decisions[addr].score)


def analyze_pointer_prefetch(pointer_update_addr_dict, prefetch_decisions, pointer_update_time_dict, time_to_update_dict, delinq_load_addr, delinq_loads_till_update, delinq_loads_till_use, all_BBs_in_loop, cfg, conf, is_ind=False, stride=0):

    if not pointer_update_addr_dict:
        return

    conf.resolved_count += 1

    pf_type = "ptr" #BB_prefetch_status(delinq_load_addr, cfg, conf)

    if is_ind:
        pf_type = "ptrind"

    available_vol_regs_list = available_vol_regs(cfg.ins_src_regs_dict, cfg.ins_dst_regs_dict)

    total_weight = sum(pointer_update_addr_dict.values())

    update_pc_weights = map(lambda tup: tuple([tup[0], round(float(tup[1])/float(total_weight), 2)]), pointer_update_addr_dict.items())

    update_pc_weights = sorted(update_pc_weights, key=operator.itemgetter(1), reverse=True)

    freq_update_pc_weight = update_pc_weights[0]

    total_time_weight = sum(pointer_update_time_dict[delinq_load_addr].values())
    
    update_pc_time_weights = map(lambda tup: tuple([tup[0], round(float(tup[1])/float(total_time_weight), 2)]), pointer_update_time_dict[delinq_load_addr].items())

    update_pc_time_weights = sorted(update_pc_time_weights, key=operator.itemgetter(1), reverse=True)

    time_to_update = None

    if delinq_load_addr in time_to_update_dict:

        time_to_update = time_to_update_dict[delinq_load_addr].items()

        time_to_update = sorted(time_to_update, key=operator.itemgetter(1), reverse=True)

    freq_delinq_loads_till_update = freq_delinq_loads_till_use = 0

    if delinq_loads_till_update:

        delinq_loads_till_update_freq_list = sorted(delinq_loads_till_update.items(), key=operator.itemgetter(1), reverse=True)
        
        freq_delinq_loads_till_update = delinq_loads_till_update_freq_list[0][0]
        
    if delinq_loads_till_use:
        
        delinq_loads_till_use_freq_list = sorted(delinq_loads_till_use.items(), key=operator.itemgetter(1), reverse=True)
        
        freq_delinq_loads_till_use = delinq_loads_till_use_freq_list[0][0]

    if freq_update_pc_weight[1] < 0.5:
        freq_update_pc = check_dominant_direction(update_pc_weights, cfg)        

        if freq_update_pc is None:
            print >> sys.stderr, "%d -  %lx no tag found <<<"%(conf.resolved_count, delinq_load_addr)
            print >> sys.stderr, "pointer chasing occuring frequently in many directions at pc:%lx" % (delinq_load_addr)
            print >> sys.stderr, update_pc_weights
            print >> sys.stderr, "\n"
            return

    freq_update_pc = freq_update_pc_weight[0]

    print >> sys.stderr,"delinq load addr: 0x%lx -- freq update pc: 0x%lx -- dominant update freq: %lf"%(delinq_load_addr, freq_update_pc, freq_update_pc_weight[1])

    if freq_update_pc in cfg.ins_tags_dict.keys():
        if freq_update_pc in cfg.ins_base_reg_dict.keys(): #(cfg.ins_tags_dict[freq_update_pc] == "Read" or cfg.ins_tags_dict[freq_update_pc] == "Write" ) and 
            
            mem_dis = cfg.ins_mem_dis_dict[freq_update_pc]

            base_reg_id = cfg.ins_base_reg_dict[freq_update_pc]
        
            updated_reg_id = cfg.ins_dst_regs_dict[freq_update_pc][0]

            if base_reg_id == 0:
                pf_type = "ind"
                print >> sys.stderr, "%d -  %lx no base_reg id <<<"%(conf.resolved_count, freq_update_pc)
                return
            elif not base_reg_id in cfg.regs_dict:
                pf_type = "ind"
                print >> sys.stderr, "%d -  %lx unusual base_reg id %d <<<"%(conf.resolved_count, freq_update_pc, base_reg_id)
                return
            
            base_reg = cfg.regs_dict[base_reg_id]
            updated_reg = cfg.regs_dict[updated_reg_id]

            score = update_pc_time_weights[0][0]
            fwd_score = 0
            if time_to_update:
                fwd_score = time_to_update[0][0]

            # it is not a nested object (reschedulable)
            reschedule =  True #is_reschedulable(delinq_load_addr, freq_update_pc, cfg)

            if not available_vol_regs_list:
                if reschedule and delinq_load_addr != freq_update_pc:
                    schedule_addr = delinq_load_addr
                else:
                    schedule_addr = freq_update_pc
                    
                usable_regs_list = static_BB_cfg.check_usable_regs_from_next_BBs(schedule_addr, cfg)

                if not usable_regs_list:
                    print >> sys.stderr, "No usable regs found"
                else:
                    available_vol_regs_list = usable_regs_list

            clobber_reg = "None"
            if available_vol_regs_list:
                for reg in available_vol_regs_list:
                    if reg in cfg.regs_dict:
                        clobber_reg = cfg.regs_dict[reg]
                        break

            #when a clobber_reg is available, it is not a nested object (reschedulable) and 
            if clobber_reg != "None" and reschedule and not are_equal(delinq_load_addr, freq_update_pc, cfg):
                
                schedule_addr = delinq_load_addr
#                reschedule_addr = static_BB_cfg.is_mem_loc_accessed_in_BB(base_reg_id, mem_dis, delinq_load_addr, cfg)
#                if not reschedule_addr == None:
#                    if reschedule_addr < schedule_addr:
#                        schedule_addr = reschedule_addr
#                        clobber_reg = "None"
            else:
                schedule_addr = freq_update_pc
                mem_dis = cfg.ins_mem_dis_dict[delinq_load_addr]
                clobber_reg = "None"
                if not reschedule:
                    print >> sys.stderr, "--nested object--"

            if is_ind:
                if freq_update_pc in cfg.ins_idx_reg_dict.keys():
                    updated_reg_id = cfg.ins_idx_reg_dict[freq_update_pc]
                else:
                    updated_reg_id = cfg.ins_dst_regs_dict[freq_update_pc][0]
                    
                if freq_update_pc in prefetch_decisions.keys():
                    mem_dis = stride * (prefetch_decisions[freq_update_pc].pd - 1)
                if mem_dis == 0:
                    mem_dis = stride

                if updated_reg_id == 0:
                    print >> sys.stderr, "%lx probably stack operation, no register updated\n"%(freq_update_pc)
                    return

                updated_reg = cfg.regs_dict[updated_reg_id]
                score = cfg.ins_mem_scale_dict[freq_update_pc]

            print >> sys.stderr, "%d>>>%lx:%d:%d"%(conf.resolved_count, delinq_load_addr, freq_delinq_loads_till_use, freq_delinq_loads_till_update)
            print >> sys.stderr, ">>> %lx:%s:%s:%s:%d:%lx:%s:%d:%d <<<\n\n"%(schedule_addr, pf_type, clobber_reg, base_reg, mem_dis, freq_update_pc, updated_reg, score, fwd_score)

            conf.indirect_pref_decisions[delinq_load_addr] = PtrPrefParams(schedule_addr, pf_type, clobber_reg, base_reg, mem_dis, freq_update_pc, updated_reg, score, fwd_score, freq_delinq_loads_till_use, freq_delinq_loads_till_update)

#        else:
#            print"%d>>> %lx non-deterministic <<<"%(conf.resolved_count, freq_update_pc)

#    else:
#        dst_reg_id = cfg.ins_dst_regs_dict[freq_update_pc][0]
#        dst_reg = cfg.regs_dict[dst_reg_id]
#        print"%d>>> %lx no tag found <<<"%(conf.resolved_count, freq_update_pc)


def analyze_non_strided_delinq_loads(global_pc_smptrace_hist, global_pc_stride_hist, prefetch_decisions, exec_file, num_samples, avg_mem_latency):

    ins_src_regs_dict = {}
    ins_dst_regs_dict = {}
    ins_tags_dict = {}
    branch_dict = {}
    routine_BB_dict = {}

    # information maps for Memory operations
    ins_base_reg_dict = {}
    ins_mem_dis_dict = {}
    ins_idx_reg_dict = {}
    ins_mem_scale_dict = {}

    global_prefetchable_pcs = []
    delinq_load_address_list = []

    for delinq_load_addr in prefetch_decisions.keys():
        pref_param = prefetch_decisions[delinq_load_addr]
        if "ptr" in pref_param.pf_type:
            delinq_load_address_list.append(delinq_load_addr)

    delinq_load_address_list = sorted(delinq_load_address_list)

    conf = Conf1(exec_file, delinq_load_address_list, num_samples, avg_mem_latency)

    irr_list = []
    print >> sys.stderr, "\nSample freq irregular accesses!\n"
    for pc in delinq_load_address_list:
        pc_smptrace_hist = global_pc_smptrace_hist[pc]
        l3mr = prefetch_decisions[pc].l3_mr
        l2mr = prefetch_decisions[pc].l2_mr
        l1mr = prefetch_decisions[pc].l1_mr
        sample_freq = float(len(pc_smptrace_hist.keys()))/float(num_samples)
        score = float(sample_freq)*float(l3mr)
        irr_list += [(pc, sample_freq, l3mr, l2mr, l1mr, score)]
        

    sorted_irr_list = sorted(irr_list, key=operator.itemgetter(5), reverse=True)

    trimmed_delinq_load_addr_list = []
    count = 0


    for tup in sorted_irr_list:
        pc = tup[0]
        sample_freq = tup[1]
        l3mr = tup[2]
        l2mr = tup[3] 
        l1mr = tup[4] 
        score = tup[5]
        if count < 15:
            trimmed_delinq_load_addr_list += [pc]
        count = count + 1
        pc_stride_hist = global_pc_stride_hist[pc]
        sorted_x = sorted(pc_stride_hist.iteritems(), key=operator.itemgetter(1), reverse=True)
        sample_count = sum([pair[1] for pair in sorted_x])
        max_stride = sorted_x[0][0] 
        max_stride_freq = float(sorted_x[0][1])/float(sample_count)

        print >> sys.stderr, "\npc:%lx  freq:%lf  l3mr:%lf  l2mr:%lf  l1mr:%lf  score:%lf"%(pc, sample_freq, l3mr, l2mr, l1mr, score)


    for delinq_load_addr in trimmed_delinq_load_addr_list: #delinq_load_address_list:

        cfg = disassm.get_func_disassm(conf.exec_file, delinq_load_addr)

        if not (cfg.ins_tags_dict[delinq_load_addr] == 'Read' or cfg.ins_tags_dict[delinq_load_addr] == 'Write'):
            continue

#        if float(len(global_pc_smptrace_hist[delinq_load_addr].keys()))/float(conf.num_samples) < 0.005:
#            continue

        (pointer_update_addr_dict, pointer_update_time_dict, time_to_update_dict, delinq_loads_till_update, delinq_loads_till_use, all_BBs_in_loop, is_ind, stride) = ins_trace_ptr_nobj_analysis.detect_pointer_chasing(global_pc_smptrace_hist, global_pc_stride_hist, delinq_load_addr, None, cfg, conf)

        analyze_pointer_prefetch(pointer_update_addr_dict, prefetch_decisions, pointer_update_time_dict, time_to_update_dict, delinq_load_addr, delinq_loads_till_update, delinq_loads_till_use, all_BBs_in_loop, cfg, conf, is_ind, stride)

#        (pointer_update_addr_dict, pointer_update_time_dict, time_to_update_dict, delinq_loads_till_update, delinq_loads_till_use, all_BBs_in_loop) = ins_trace_analysis.detect_pointer_chasing(global_pc_smptrace_hist, delinq_load_addr, prefetch_decisions, cfg, conf)

#        analyze_pointer_prefetch(pointer_update_addr_dict, pointer_update_time_dict, time_to_update_dict, delinq_load_addr, delinq_loads_till_update, delinq_loads_till_use, all_BBs_in_loop, cfg, conf)

        if delinq_load_addr in conf.indirect_pref_decisions:
            do_cost_benefit_analysis(cfg, conf, delinq_load_addr, prefetch_decisions)
        
    decide_prefetch_schedules(cfg, conf)
    print_indirect_prefetch_decisions(conf)



def main():

    ins_src_regs_dict = {}
    ins_dst_regs_dict = {}
    ins_tags_dict = {}
    branch_dict = {}
    routine_BB_dict = {}

    # information maps for Memory operations
    ins_base_reg_dict = {}
    ins_mem_dis_dict = {}
    ins_idx_reg_dict = {}
    ins_mem_scale_dict = {}

    global_prefetchable_pcs = []

    global_pc_smptrace_hist = {}
    global_pc_stride_hist = {}

    conf = Conf()

    if not conf.hex_address == None:
        delinq_load_addr = int(conf.hex_address, 16)
    else:
        delinq_load_addr = int(conf.dec_address, 10)

    delinq_load_address_list = get_delinq_load_address_list(conf)

    if delinq_load_address_list == None:
        delinq_load_address_list = [delinq_load_addr]

    listing = os.listdir(conf.path)

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

        for (pc_rdist_hist, pc_stride_hist, pc_freq_hist, pc_time_hist, pc_corr_hist, pc_fwd_rdist_hist, pc_smptrace_hist) in burst_hists:
            continue

        ins_trace_ptr_nobj_analysis.add_trace_to_global_pc_smptrace_hist(global_pc_smptrace_hist, pc_smptrace_hist)
        ins_trace_ptr_nobj_analysis.add_to_pc_stride_hist(pc_stride_hist, global_pc_stride_hist)

    print >> sys.stderr, "Starting trace analysis..."

    for delinq_load_addr in delinq_load_address_list:

        cfg = disassm.get_func_disassm(conf.exec_file, delinq_load_addr)
    
        if not (cfg.ins_tags_dict[delinq_load_addr] == 'Read' or cfg.ins_tags_dict[delinq_load_addr] == 'Write'):
            continue

        print >> sys.stderr, "Sample frequency %lx: %lf"%(delinq_load_addr, float(len(pc_smptrace_hist.keys()))/float(conf.num_samples))

        (pointer_update_addr_dict, pointer_update_time_dict, time_to_update_dict, delinq_loads_till_update, delinq_loads_till_use, all_BBs_in_loop, is_ind, stride) = ins_trace_ptr_nobj_analysis.detect_pointer_chasing(global_pc_smptrace_hist, global_pc_stride_hist, delinq_load_addr, None, cfg, conf)

#        analyze_pointer_prefetch(pointer_update_addr_dict, pointer_update_time_dict, time_to_update_dict, delinq_load_addr, delinq_loads_till_update, delinq_loads_till_use, all_BBs_in_loop, cfg, conf, is_ind, stride)

        analyze_pointer_prefetch(pointer_update_addr_dict, [], pointer_update_time_dict, time_to_update_dict, delinq_load_addr, delinq_loads_till_update, delinq_loads_till_use, all_BBs_in_loop, cfg, conf, is_ind, stride)

    decide_prefetch_schedules(cfg, conf)
    print_indirect_prefetch_decisions(conf)


if __name__ == "__main__":
    main()
