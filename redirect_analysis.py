#!/usr/bin/python

import string
import sys
import re
import operator

from optparse import OptionParser
import subprocess

class Conf:
    def __init__(self):
        parser = OptionParser("usage: %prog [OPTIONS...] INFILE")

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
                          help="Specify the executablt to inspect")

        (opts, args) = parser.parse_args()

        self.dec_address = opts.dec_address

        self.hex_address = opts.hex_address
        self.exec_file = opts.exec_file

        self.re_hex_address = re.compile("0[xX][0-9a-fA-F]+")

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

    tag_list = ['IndirectBranch', 'IndirectCondBranch', 'Branch', 'CondBranch', 'Call', 'Ret', 'Stack', 'Read', 'Write']

    line_tokens = routine.split('\n')

    target_address = 0
    tag_br_target_for_this_pc = 0

    for line in line_tokens:

        tokens = line.split()

        if(len(tokens) > 0 and tokens[0] == "instr:"):
            instr_addr = int(tokens[1], 16)
            routine_addr_range.append(instr_addr)
            target_address = conf.re_hex_address.findall(line)

            if tag_br_target_for_this_pc != 0:
                branch_dict[tag_br_target_for_this_pc].append(instr_addr)
                tag_br_target_for_this_pc = 0

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

            ins_src_regs_dict[instr_addr] =  src_regs
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

def build_static_routine_CFG(ins_tags_dict, branch_dict, routine_addr_range):

    BB_dict = {}
    BB = []

    branch_tags = ['IndirectBranch', 'IndirectCondBranch', 'Branch', 'CondBranch', 'Ret']


    for pc in routine_addr_range:
        BB.append(pc)
        if pc in ins_tags_dict.keys():
            if ins_tags_dict[pc] in branch_tags:
                BB_start_pc = BB[0]
                BB_dict[BB_start_pc] = BB
                BB = []

    br_target_BBs = []

    for branches in branch_dict.keys():
        br_target_list = branch_dict[branches]
        for br_target in br_target_list:
            if not br_target in BB_dict.keys():
                if not br_target in br_target_BBs:
                    br_target_BBs.append(br_target)


    while len(br_target_BBs) > 0:
        BB = []
        br_target = br_target_BBs.pop()
        
        i = routine_addr_range.index(br_target)

        for pc in routine_addr_range[i:len(routine_addr_range)]:

            BB.append(pc)

            if pc in ins_tags_dict.keys():
                if ins_tags_dict[pc] in branch_tags:
                    BB_start_pc = BB[0]
                    BB_dict[BB_start_pc] = BB
                    BB = []

    return BB_dict

def discover_BB_for_address(instr_addr, routine_BB_dict):

    BBs_list = []

    for BB_addr in routine_BB_dict.keys():
        BB_addr_range = routine_BB_dict.get(BB_addr)
        if instr_addr in BB_addr_range:
            BB_addr_len_tup = (BB_addr, len(BB_addr_range))
            BBs_list.append(BB_addr_len_tup)

    (BB_addr, BB_len) = max(BBs_list, key=lambda x: x[1])

    #return the longest BB containing the instruction
    return BB_addr

def get_entry_point_branches(BB_addr, routine_BB_dict, branch_dict):

    entry_point_branches = []

    for branch in branch_dict.keys():
        
        # if the basic block address is in the branch targets
        if BB_addr in branch_dict[branch]:
            entry_point_branches.append(branch)

    return entry_point_branches
        
def check_dependencies_in_reverse(delinq_load_addr, BB_addr, ins_src_regs_dict, ins_dst_regs_dict, ins_base_reg_dict, routine_BB_dict, ins_tags_dict, branch_dict, track_reg=None):

    pointer_update_dep_list = []

    delinq_load_base_reg_id = ins_base_reg_dict[delinq_load_addr]
    
    reversed_BB_addr_range = sorted(routine_BB_dict[BB_addr], reverse=True)

    if track_reg == None:
        track_reg = delinq_load_base_reg_id

    for instr_addr in reversed_BB_addr_range:
        
        if len(ins_dst_regs_dict[instr_addr]) > 0:
            
            reg_updated = ins_dst_regs_dict[instr_addr][0] 
            reg_read = ins_src_regs_dict[instr_addr][0]
            
            tag = None
            if instr_addr in ins_tags_dict.keys():
                tag = ins_tags_dict[instr_addr]

            if reg_updated == track_reg:
                
                # p = p->next
                if tag == "Read":
                    pointer_update_dep_list.append(instr_addr)
                    track_reg = None
                    return pointer_update_dep_list
                
                # move r1, r2  -- not mem op
                elif tag != "Read":
                    pointer_update_dep_list.append(instr_addr)
                    track_reg = reg_read
            
#                else:
#                    pointer_update_dep_list.append(instr_addr)
#                    track_reg = reg_read

    
    if track_reg != None:
        entry_point_branches = get_entry_point_branches(BB_addr, routine_BB_dict, branch_dict)

        for entry_point_branch in entry_point_branches:
            preceding_BB_addr = discover_BB_for_address(entry_point_branch, routine_BB_dict)

            branched_dep_list = check_dependencies_in_reverse(delinq_load_addr, preceding_BB_addr, ins_src_regs_dict, ins_dst_regs_dict, ins_base_reg_dict, routine_BB_dict, ins_tags_dict, branch_dict, track_reg)
            pointer_update_dep_list.append(branched_dep_list)

    return pointer_update_dep_list


def discover_pointer_chasing(routine_BB_dict, ins_src_regs_dict, ins_dst_regs_dict, ins_tags_dict, branch_dict, routine_addr_range, delinq_load_addr, ins_base_reg_dict, ins_mem_dis_dict, ins_idx_reg_dict, ins_mem_scale_dict):
    
    print delinq_load_addr

    pointer_update_ins_list = []

    if delinq_load_addr in ins_tags_dict.keys():
        ins_tag = ins_tags_dict.get(delinq_load_addr)

        if ins_tag == "Read":
            None
    
    if not delinq_load_addr in ins_base_reg_dict.keys():
        return

    BB_addr = discover_BB_for_address(delinq_load_addr, routine_BB_dict)

    entry_point_branches = get_entry_point_branches(BB_addr, routine_BB_dict, branch_dict)

    for entry_point_branch in entry_point_branches:
        preceding_BB_addr = discover_BB_for_address(entry_point_branch, routine_BB_dict)

        pointer_update_dep_list = check_dependencies_in_reverse(delinq_load_addr, preceding_BB_addr, ins_src_regs_dict, ins_dst_regs_dict, ins_base_reg_dict, routine_BB_dict, ins_tags_dict, branch_dict)

        if len(pointer_update_dep_list) > 0:
            print "dep list"
            print pointer_update_dep_list

    delinq_load_base_reg_id = ins_base_reg_dict[delinq_load_addr]
    if len(ins_dst_regs_dict[delinq_load_addr]) > 0:
        reg_updated_at_delinq_load = ins_dst_regs_dict[delinq_load_addr][0]
    else:
        reg_updated_at_delinq_load = None
        
    if delinq_load_base_reg_id == reg_updated_at_delinq_load:
        print "self update instruction p = p->next @ %x"%(delinq_load_addr)
        pointer_update_ins_list.append(delinq_load_addr)
        return

    BBs_to_check = []

    BBs_to_check.append(BB_addr)

    checked_BBs = []
    
    reg_update_ins = []
    updated_reg_read_ins = []

    src_regs_at_update_ins = []

    while len(BBs_to_check) > 0:

        curr_BB = BBs_to_check.pop()

        BB_addr_range = routine_BB_dict.get(curr_BB)

        for instr_addr in BB_addr_range:
            if instr_addr == delinq_load_addr:
                continue

            if len(ins_dst_regs_dict[instr_addr]) > 0:
                reg_updated = ins_dst_regs_dict[instr_addr][0]
                
                if delinq_load_base_reg_id == reg_updated:
                    if not instr_addr in reg_update_ins:
                        reg_update_ins.append(instr_addr)
                    
                    reg_read = ins_src_regs_dict[instr_addr][0]
                    if not reg_read in src_regs_at_update_ins:
                        src_regs_at_update_ins.append(reg_read)
                    
            if len(ins_src_regs_dict[instr_addr]) > 0:
                reg_read = ins_src_regs_dict[instr_addr][0]
                
                if  reg_updated_at_delinq_load == reg_read:
                    if not instr_addr in updated_reg_read_ins:
                        updated_reg_read_ins.append(instr_addr)

        checked_BBs.append(curr_BB)

        if instr_addr in branch_dict.keys():
            curr_BB_exit_targets_list = branch_dict[instr_addr]
            for br_target in curr_BB_exit_targets_list:
                if br_target in checked_BBs:
                    continue
                else:
                    BBs_to_check.append(br_target)

    print "base reg at %x updated at"%(delinq_load_addr)
    print reg_update_ins

    print "reg updated at %x read at"%(delinq_load_addr)
    print updated_reg_read_ins

    print "src regs"
    print src_regs_at_update_ins

    BB_addr = discover_BB_for_address(delinq_load_addr, routine_BB_dict)

    BBs_to_check = []

    BBs_to_check.append(BB_addr)

    checked_BBs = []
    
    updated_reg_updated_ins = []


    while len(BBs_to_check) > 0:

        curr_BB = BBs_to_check.pop()
                
        BB_addr_range = routine_BB_dict.get(curr_BB)
                
        for instr_addr in BB_addr_range:
            if instr_addr == delinq_load_addr:
                continue

            reg_updated = reg_read = None

            if len(ins_dst_regs_dict[instr_addr]) > 0:
                reg_updated = ins_dst_regs_dict[instr_addr][0]

            if len(ins_src_regs_dict[instr_addr]) > 0:
                reg_read = ins_src_regs_dict[instr_addr][0]
                
            if reg_updated_at_delinq_load == reg_updated:
                if not instr_addr in updated_reg_updated_ins:
                    updated_reg_updated_ins.append(instr_addr)
            elif delinq_load_base_reg_id == reg_updated and reg_read == reg_updated_at_delinq_load: # p = p->next
                if reg_read in src_regs_at_update_ins:
                    src_regs_at_update_ins.remove(reg_read)
                if not instr_addr in updated_reg_updated_ins and not instr_addr in pointer_update_ins_list:
                    pointer_update_ins_list.append(instr_addr)

            checked_BBs.append(curr_BB)
                                
            if instr_addr in branch_dict.keys():
                curr_BB_exit_targets_list = branch_dict[instr_addr]
                for br_target in curr_BB_exit_targets_list:
                    if br_target in checked_BBs:
                        continue
                    else:
                        BBs_to_check.append(br_target)

    
    print "src regs"
    print src_regs_at_update_ins

    last_update_ins_reg_to_check = {}

    for src_reg_to_check in src_regs_at_update_ins:
   
        BB_addr = discover_BB_for_address(delinq_load_addr, routine_BB_dict)
     
        BBs_to_check = []

        BBs_to_check.append(BB_addr)
        
        checked_BBs = []

        while len(BBs_to_check) > 0:

            curr_BB = BBs_to_check.pop()
                
            BB_addr_range = routine_BB_dict.get(curr_BB)
                
            for instr_addr in BB_addr_range:

                reg_updated = reg_read = None

                if len(ins_dst_regs_dict[instr_addr]) > 0:
                    reg_updated = ins_dst_regs_dict[instr_addr][0]

                if len(ins_src_regs_dict[instr_addr]) > 0:
                    reg_read = ins_src_regs_dict[instr_addr][0]
                
                if src_reg_to_check == reg_updated:
                    if not reg_updated in last_update_ins_reg_to_check.keys():
                        last_update_ins_reg_to_check[reg_updated] = [instr_addr]
                    elif not instr_addr in last_update_ins_reg_to_check[reg_updated]:
                        last_update_ins_reg_to_check[reg_updated].append(instr_addr)


                checked_BBs.append(curr_BB)
                                
                if instr_addr in branch_dict.keys():
                    curr_BB_exit_targets_list = branch_dict[instr_addr]
                    for br_target in curr_BB_exit_targets_list:
                        if br_target in checked_BBs:
                            continue
                        else:
                            BBs_to_check.append(br_target)


    print "\n\n"
    print "p = p->next @"
    print pointer_update_ins_list

    print "src register updates @"
    print last_update_ins_reg_to_check

    print "\n\n"
    print branch_dict
    print "\n\n"
    print routine_BB_dict

        

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

    conf = Conf()

    delinq_load_addr = int(conf.dec_address, 10)
    
    routine = subprocess.Popen(["/home/muneeb/pin-2.8-36111-gcc.3.4.6-ia32_intel64-linux/source/tools/ManualExamples/obj-intel64/get_routine", "-a", conf.dec_address,"-i", conf.exec_file], stdout=subprocess.PIPE).communicate()[0]

    [ins_src_regs_dict, ins_dst_regs_dict, ins_tags_dict, branch_dict, routine_addr_range, ins_base_reg_dict, ins_mem_dis_dict, ins_idx_reg_dict, ins_mem_scale_dict] = parse_routine_info(routine, conf)

    routine_BB_dict = build_static_routine_CFG(ins_tags_dict, branch_dict, routine_addr_range)

    discover_pointer_chasing(routine_BB_dict, ins_src_regs_dict, ins_dst_regs_dict, ins_tags_dict, branch_dict, routine_addr_range, delinq_load_addr, 
                             ins_base_reg_dict, ins_mem_dis_dict, ins_idx_reg_dict, ins_mem_scale_dict)

if __name__ == "__main__":
    main()
