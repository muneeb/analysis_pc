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

#            print line

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

#           print line
#           print "\n"

    return [ins_src_regs_dict, ins_dst_regs_dict, ins_tags_dict, branch_dict, routine_addr_range]

def build_static_BB_graph(ins_tags_dict, branch_dict, routine_addr_range):

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

    return BB_dict

def discover_pointer_chasing(routine_BB_dict, ins_src_regs_dict, ins_dst_regs_dict, ins_tags_dict, branch_dict, routine_addr_range, delinq_load_addr):
    
    

def main():

    ins_src_regs_dict = {}
    ins_dst_regs_dict = {}
    ins_tags_dict = {}
    branch_dict = {}
    routine_BB_dict = {}

    conf = Conf()
    
    routine = subprocess.Popen(["/home/muneeb/pin-2.8-36111-gcc.3.4.6-ia32_intel64-linux/source/tools/ManualExamples/obj-intel64/get_routine", "-a", conf.dec_address,"-i", conf.exec_file], stdout=subprocess.PIPE).communicate()[0]

    [ins_src_regs_dict, ins_dst_regs_dict, ins_tags_dict, branch_dict, routine_addr_range] = parse_routine_info(routine, conf)

    routine_BB_dict = build_static_BB_graph(ins_tags_dict, branch_dict, routine_addr_range)

if __name__ == "__main__":
    main()
