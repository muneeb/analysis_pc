#!/usr/bin/python

import string
import sys
import re
import operator
import os
import pyusf
import utils

from uart.hist import Hist
import uart.sample_filter as sample_filter

from optparse import OptionParser
import subprocess
import trace_analysis
import static_BB_cfg

#class PrefParams:

#    def __init__(self, delinq_load_addr, pf_type, l1_mr, l2_mr, l3_mr):
#        self.delinq_load_addr = delinq_load_addr
#        self.pf_type = pf_type
#        self.l1_mr = l1_mr
#        self.l2_mr = l2_mr
#        self.l3_mr = l3_mr

class PtrPrefParams:

    def __init__(self, schedule_addr, pf_type, clobber_reg, base_reg, mem_dis, freq_update_pc, updated_reg, score, fwd_score):
        
        self.schedule_addr = schedule_addr
        self.pf_type = pf_type
        self.clobber_reg = clobber_reg
        self.base_reg = base_reg
        self.mem_dis = mem_dis
        self.freq_update_pc = freq_update_pc
        self.updated_reg = updated_reg
        self.score = score
        self.fwd_score = fwd_score
        
class Conf1:

    def __init__(self, exec_file, all_delinq_loads_list):
        self.exec_file = exec_file

        self.re_hex_address = re.compile("0[xX][0-9a-fA-F]+")

        self.line_size = 64
        self.BB_reg_prefetch_dict = {}
        self.indirect_pref_decisions = {}
        self.all_delinq_loads_list = all_delinq_loads_list
        self.resolved_count = 0

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

class CFG_Info:

    def __init__(self, ins_src_regs_dict, ins_dst_regs_dict, ins_tags_dict, branch_dict, routine_addr_range, ins_base_reg_dict, ins_mem_dis_dict, ins_idx_reg_dict, ins_mem_scale_dict, BB_dict):
        self.ins_src_regs_dict = ins_src_regs_dict
        self.ins_dst_regs_dict = ins_dst_regs_dict
        self.ins_tags_dict = ins_tags_dict
        self.branch_dict = branch_dict
        self.routine_addr_range = routine_addr_range
        self.ins_base_reg_dict = ins_base_reg_dict
        self.ins_mem_dis_dict = ins_mem_dis_dict
        self.ins_idx_reg_dict = ins_idx_reg_dict
        self.ins_mem_scale_dict = ins_mem_scale_dict
        self.BB_dict = BB_dict
        self.vol_regs_dict = {17:"rdx", 18:"rcx", 19:"rax", 20:"r8", 21:"r9", 22:"r10", 23:"r11"}
        self.regs_dict = {12:"rdi", 13:"rsi", 16:"rbx", 17:"rdx", 18:"rcx", 19:"rax", 20:"r8", 21:"r9", 22:"r10", 23:"r11", 24:"r12", 25:"r13", 26:"r14", 27:"r15"}

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

def parse_routine_info(routine, conf):

    ins_src_regs_dict = {}
    ins_dst_regs_dict = {}
    ins_tags_dict = {}
    branch_dict = {}
    routine_addr_range = []

    # information maps for Memory operations
    ins_base_reg_dict = {}
    ins_mem_dis_dict = {}
    ins_idx_reg_dict = {}
    ins_mem_scale_dict = {}

    tag_list = ['IndirectBranch', 'IndirectCondBranch', 'Branch', 'CondBranch', 'Call', 'Ret', 'Stack', 'Read', 'Write', 'Move', 'Nop']

    line_tokens = routine.split('\n')

    target_address = 0
    tag_br_target_for_this_pc = 0

    is_nop = False

    for line in line_tokens:

        tokens = line.split()

        if(len(tokens) > 0 and tokens[0] == "instr:"):
            instr_addr = int(tokens[1], 16)
            routine_addr_range.append(instr_addr)
            target_address = conf.re_hex_address.findall(line)

            if tag_br_target_for_this_pc != 0:
                branch_dict[tag_br_target_for_this_pc].append(instr_addr)
                tag_br_target_for_this_pc = 0

            instr = tokens[2]
#            if "nop" in instr:
#                is_nop = True

            print line

        elif(len(tokens) > 0):
            
            src_regs = []
            dst_regs = []
            
            for reg_info in tokens:
                
                if reg_info.find("R:") != -1:
                    reg_info_tokens = reg_info.split(":")
                    reg_id = int(reg_info_tokens[1], 16)
                    if not reg_id in src_regs:
                        src_regs.append(reg_id)

                elif reg_info.find("W:") != -1:
                    reg_info_tokens = reg_info.split(":")
                    reg_id = int(reg_info_tokens[1], 16)
                    if not reg_id in dst_regs:
                        dst_regs.append(reg_id)

                elif reg_info.find("MemBaseReg:") != -1:
                    reg_info_tokens = reg_info.split(":")
                    base_reg_id = int(reg_info_tokens[1], 16)
                    ins_base_reg_dict[instr_addr] = base_reg_id

                elif reg_info.find("MemDis:") != -1:
                    reg_info_tokens = reg_info.split(":")
                    mem_dis = int(reg_info_tokens[1], 16)
                    ins_mem_dis_dict[instr_addr] = mem_dis

                elif reg_info.find("MemIdxReg:") != -1:
                    reg_info_tokens = reg_info.split(":")
                    idx_reg_id = int(reg_info_tokens[1], 16)
                    ins_idx_reg_dict[instr_addr] = idx_reg_id

                elif reg_info.find("MemScale:") != -1:
                    reg_info_tokens = reg_info.split(":")
                    mem_scale = int(reg_info_tokens[1], 16)
                    ins_mem_scale_dict[instr_addr] = mem_scale

#            if is_nop:
#                is_nop = False
#                ins_tag = "Nop"
#                ins_tags_dict[instr_addr] = ins_tag
#                print line+"  "+ins_tag
#                continue

            ins_src_regs_dict[instr_addr] =  src_regs

            if len(dst_regs) > 0:
                ins_dst_regs_dict[instr_addr] =  dst_regs

            ins_tag = tokens.pop()

            if( ins_tag in tag_list ):
                ins_tags_dict[instr_addr] = ins_tag

            if( ins_tag == 'Branch'):
                br_target_pc = int(target_address[0], 16)
                branch_dict[instr_addr] = [br_target_pc]
            elif( ins_tag == 'CondBranch'):
                br_target_pc = int(target_address[0], 16)
                tag_br_target_for_this_pc = instr_addr #add information for fall through in next iteration when address for next instruction is discovered
                branch_dict[instr_addr] = [br_target_pc]
            elif( ins_tag == 'IndirectBranch' or  ins_tag == 'Ret'):
                br_target_pc = 0   # target instruction is not known
                branch_dict[instr_addr] = [br_target_pc]
            elif( ins_tag == 'IndirectCondBranch'):
                br_target_pc = 0   # target instruction is not known
                tag_br_target_for_this_pc = instr_addr #add information for fall through in next iteration when address for next instruction is discovered
                branch_dict[instr_addr] = [br_target_pc]

            print line


    return [ins_src_regs_dict, ins_dst_regs_dict, ins_tags_dict, branch_dict, routine_addr_range, ins_base_reg_dict, ins_mem_dis_dict, ins_idx_reg_dict, ins_mem_scale_dict]

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
def add_to_BB_indirect_pref_decisions(delinq_load_addr, cfg, conf):

    BB_addr = static_BB_cfg.discover_BB_for_address(delinq_load_addr, cfg.BB_dict)
    base_reg_id = cfg.ins_base_reg_dict[delinq_load_addr]
    mem_dis = cfg.ins_mem_dis_dict[delinq_load_addr]

    if BB_addr in conf.BB_reg_prefetch_dict:
        if base_reg_id in conf.BB_reg_prefetch_dict[BB_addr]:
            conf.BB_reg_prefetch_dict[BB_addr][base_reg_id] += [(delinq_load_addr, mem_dis)]
        else:
            conf.BB_reg_prefetch_dict[BB_addr][base_reg_id] = [(delinq_load_addr, mem_dis)]
    else:
        conf.BB_reg_prefetch_dict[BB_addr] = {}
        conf.BB_reg_prefetch_dict[BB_addr][base_reg_id] = [(delinq_load_addr, mem_dis)]


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

def decide_prefetch_schedules(cfg, conf):

    BB_addr_list = sorted(conf.BB_reg_prefetch_dict.keys())

    for BB_addr in BB_addr_list:
        for base_reg_id in conf.BB_reg_prefetch_dict[BB_addr].keys():

#            print ">>>>>>"+str(conf.BB_reg_prefetch_dict[BB_addr][base_reg_id])

            addr_list = map(lambda x: x[0], conf.BB_reg_prefetch_dict[BB_addr][base_reg_id])
            mem_dis_list = map(lambda x: x[1], conf.BB_reg_prefetch_dict[BB_addr][base_reg_id])
            max_dis = max(mem_dis_list)
            min_dis = min(mem_dis_list)

#            print ">>>>>>"+str(addr_list)

            mem_dis_diff = max_dis - min_dis

            if mem_dis_diff == 0:
                pf_type = "ptr"
            elif mem_dis_diff < conf.line_size:
                pf_type = "ptradj"
            else:
                pf_type = "ptradj2"

            #schedule earliest
            schedule_addr = min(addr_list)

            conf.indirect_pref_decisions[schedule_addr].pf_type = pf_type
            
            for addr in addr_list:
                if addr == schedule_addr:
                    continue
                del conf.indirect_pref_decisions[addr]

            print">>> %lx:%s:%s:%s:%d:%lx:%s:%d:%d <<<"%(conf.indirect_pref_decisions[schedule_addr].schedule_addr, 
                                                     conf.indirect_pref_decisions[schedule_addr].pf_type, 
                                                     conf.indirect_pref_decisions[schedule_addr].clobber_reg, 
                                                     conf.indirect_pref_decisions[schedule_addr].base_reg, 
                                                     conf.indirect_pref_decisions[schedule_addr].mem_dis, 
                                                     conf.indirect_pref_decisions[schedule_addr].freq_update_pc, 
                                                     conf.indirect_pref_decisions[schedule_addr].updated_reg, 
                                                     conf.indirect_pref_decisions[schedule_addr].score, 
                                                     conf.indirect_pref_decisions[schedule_addr].fwd_score)
            print ">>>grouped>>>"+str(addr_list)

def analyze_pointer_prefetch(pointer_update_addr_dict, pointer_update_time_dict, time_to_update_dict, delinq_load_addr, delinq_loads_till_update, delinq_loads_till_use, all_BBs_in_loop, cfg, conf):

    if not pointer_update_addr_dict:
        return

    conf.resolved_count += 1

    pf_type = BB_prefetch_status(delinq_load_addr, cfg, conf)


    available_vol_regs_list = available_vol_regs(cfg.ins_src_regs_dict, cfg.ins_dst_regs_dict)

    total_weight = sum(pointer_update_addr_dict.values())

    update_pc_weights = map(lambda tup: tuple([tup[0], round(float(tup[1])/float(total_weight), 2)]), pointer_update_addr_dict.items())

    update_pc_weights = sorted(update_pc_weights, key=operator.itemgetter(1), reverse=True)

    freq_update_pc_weight = update_pc_weights[0]

    total_time_weight = sum(pointer_update_time_dict[delinq_load_addr].values())
    
    update_pc_time_weights = map(lambda tup: tuple([tup[0], round(float(tup[1])/float(total_time_weight), 2)]), pointer_update_time_dict[delinq_load_addr].items())

    update_pc_time_weights = sorted(update_pc_time_weights, key=operator.itemgetter(1), reverse=True)

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
            print >> sys.stderr, ">>>pointer chasing occuring frequently in many directions at pc:%lx" % (delinq_load_addr)
            print >> sys.stderr, update_pc_weights
            print >> sys.stderr, "\n"
            return

    freq_update_pc = freq_update_pc_weight[0]

    if freq_update_pc in cfg.ins_tags_dict.keys():
        if (cfg.ins_tags_dict[freq_update_pc] == "Read" or cfg.ins_tags_dict[freq_update_pc] == "Write") and freq_update_pc in cfg.ins_base_reg_dict.keys():
        
            mem_dis = cfg.ins_mem_dis_dict[freq_update_pc]

            base_reg_id = cfg.ins_base_reg_dict[freq_update_pc]
        
            updated_reg_id = cfg.ins_dst_regs_dict[freq_update_pc][0]

            if base_reg_id == 0:
                pf_type = "ind"
                print"%d>>> %lx no base_reg id <<<"%(conf.resolved_count, freq_update_pc)
                return

            add_to_BB_indirect_pref_decisions(delinq_load_addr, cfg, conf)
                
            base_reg = cfg.regs_dict[base_reg_id]
            updated_reg = cfg.regs_dict[updated_reg_id]

            score = update_pc_time_weights[0][0]
            fwd_score = time_to_update[0][0]

            reschedule =  is_reschedulable(delinq_load_addr, freq_update_pc, cfg)

            if not available_vol_regs_list:
                if reschedule and delinq_load_addr != freq_update_pc:
                    schedule_addr = delinq_load_addr
                else:
                    schedule_addr = freq_update_pc
                    
                usable_regs_list = static_BB_cfg.check_usable_regs_from_next_BBs(schedule_addr, cfg)

                if not usable_regs_list:
                    print >> sys.stderr, ">>>No usable regs found"
                else:
                    available_vol_regs_list = usable_regs_list

            clobber_reg = "None"
            if available_vol_regs_list:
                for reg in available_vol_regs_list:
                    if reg in cfg.regs_dict:
                        clobber_reg = cfg.regs_dict[reg]
                        break
    
            print "%%%"
            print clobber_reg

            if clobber_reg != "None" and reschedule and delinq_load_addr != freq_update_pc:
                
                schedule_addr = delinq_load_addr
                reschedule_addr = static_BB_cfg.is_mem_loc_accessed_in_BB(base_reg_id, mem_dis, delinq_load_addr, cfg)
                if not reschedule_addr == None:
                    if reschedule_addr < schedule_addr:
                        schedule_addr = reschedule_addr
                        clobber_reg = "None"
            else:
                schedule_addr = freq_update_pc
                mem_dis = cfg.ins_mem_dis_dict[delinq_load_addr]
                clobber_reg = "None"
                if not reschedule:
                    print ">>> nested object"

            print"%d>>>%lx:%d:%d"%(conf.resolved_count, delinq_load_addr, freq_delinq_loads_till_use, freq_delinq_loads_till_update)
            print">>> %lx:%s:%s:%s:%d:%lx:%s:%d:%d <<<"%(schedule_addr, pf_type, clobber_reg, base_reg, mem_dis, freq_update_pc, updated_reg, score, fwd_score)
            
            conf.indirect_pref_decisions[delinq_load_addr] = PtrPrefParams(schedule_addr, pf_type, clobber_reg, base_reg, mem_dis, freq_update_pc, updated_reg, score, fwd_score)

#    else:
#        dst_reg_id = cfg.ins_dst_regs_dict[freq_update_pc][0]
#        dst_reg = cfg.regs_dict[dst_reg_id]
#        print"%d>>> %ld:%s:%s:%s:%s <<<"%(conf.resolved_count, freq_update_pc, pf_type, "None", dst_reg, "None")

def analyze_non_strided_delinq_loads(global_pc_smptrace_hist, prefetch_decisions, exec_file):

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
        if pref_param.pf_type == "ptr":
            delinq_load_address_list.append(delinq_load_addr)

    delinq_load_address_list = sorted(delinq_load_address_list)

    conf = Conf1(exec_file, delinq_load_address_list)

    print "Starting trace analysis..."

    for delinq_load_addr in delinq_load_address_list:

        print "--%lu--" % (delinq_load_addr)

        routine = subprocess.Popen(["/home/muneeb/pin-2.8-36111-gcc.3.4.6-ia32_intel64-linux/source/tools/ManualExamples/obj-intel64/get_routine", "-a", str(delinq_load_addr),"-i", conf.exec_file], stdout=subprocess.PIPE).communicate()[0]

        [ins_src_regs_dict, ins_dst_regs_dict, ins_tags_dict, branch_dict, routine_addr_range, ins_base_reg_dict, ins_mem_dis_dict, ins_idx_reg_dict, ins_mem_scale_dict] = parse_routine_info(routine, conf)

        BB_dict = static_BB_cfg.build_static_routine_CFG(ins_tags_dict, branch_dict, routine_addr_range)
    
        cfg = CFG_Info(ins_src_regs_dict, ins_dst_regs_dict, ins_tags_dict, branch_dict, routine_addr_range, ins_base_reg_dict, ins_mem_dis_dict, ins_idx_reg_dict, ins_mem_scale_dict, BB_dict)

   #     pointer_update_instr_list = static_BB_cfg.discover_pointer_chasing_static(cfg, delinq_load_addr)
        
        (pointer_update_addr_dict, pointer_update_time_dict, time_to_update_dict, delinq_loads_till_update, delinq_loads_till_use, all_BBs_in_loop) = trace_analysis.detect_pointer_chasing(global_pc_smptrace_hist, delinq_load_addr, prefetch_decisions, cfg, conf)

        print pointer_update_addr_dict.items()

        analyze_pointer_prefetch(pointer_update_addr_dict, pointer_update_time_dict, time_to_update_dict, delinq_load_addr, delinq_loads_till_update, delinq_loads_till_use, all_BBs_in_loop, cfg, conf)
        
        print "+++"
        print delinq_loads_till_update.items()

        print "\n\n"
        
    decide_prefetch_schedules(cfg, conf)


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

    conf = Conf()

    delinq_load_addr = int(conf.dec_address, 10)

    delinq_load_address_list = get_delinq_load_address_list(conf)

    if delinq_load_address_list == None:
        delinq_load_address_list = [delinq_load_addr]

    listing = os.listdir(conf.path)

    print "building trace maps..."

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

        trace_analysis.add_trace_to_global_pc_smptrace_hist(global_pc_smptrace_hist, pc_smptrace_hist)

    print "Starting trace analysis..."

    for delinq_load_addr in delinq_load_address_list:

        print "--%lu--" % (delinq_load_addr)

        routine = subprocess.Popen(["/home/muneeb/pin-2.8-36111-gcc.3.4.6-ia32_intel64-linux/source/tools/ManualExamples/obj-intel64/get_routine", "-a", str(delinq_load_addr),"-i", conf.exec_file], stdout=subprocess.PIPE).communicate()[0]

        [ins_src_regs_dict, ins_dst_regs_dict, ins_tags_dict, branch_dict, routine_addr_range, ins_base_reg_dict, ins_mem_dis_dict, ins_idx_reg_dict, ins_mem_scale_dict] = parse_routine_info(routine, conf)

        BB_dict = static_BB_cfg.build_static_routine_CFG(ins_tags_dict, branch_dict, routine_addr_range)
    
        cfg = CFG_Info(ins_src_regs_dict, ins_dst_regs_dict, ins_tags_dict, branch_dict, routine_addr_range, ins_base_reg_dict, ins_mem_dis_dict, ins_idx_reg_dict, ins_mem_scale_dict, BB_dict)

   #     pointer_update_instr_list = static_BB_cfg.discover_pointer_chasing_static(cfg, delinq_load_addr)
        
        (pointer_update_addr_dict, pointer_update_time_dict, time_to_update_dict, delinq_loads_till_update, delinq_loads_till_use, all_BBs_in_loop) = trace_analysis.detect_pointer_chasing(global_pc_smptrace_hist, delinq_load_addr, cfg, conf)

        print pointer_update_addr_dict.items()

        analyze_pointer_prefetch(pointer_update_addr_dict, pointer_update_time_dict, time_to_update_dict, delinq_load_addr, delinq_loads_till_update, delinq_loads_till_use, all_BBs_in_loop, cfg, conf)

        print "\n\n"
        
    decide_prefetch_schedules(cfg, conf)

if __name__ == "__main__":
    main()
