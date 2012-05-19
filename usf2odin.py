#!/usr/bin/python
import sys
import optparse
import pyusf
import pyodin
import lrumodel

def print_error(e):
    print >> sys.stderr, e

def print_and_exit(e, ret = 1):
    print_error(e)
    sys.exit(ret)

def parse_args():
    usage = "usage: %prog [OPTIONS...] INFILE"
    parser = optparse.OptionParser(usage)
    parser.add_option("-o", "--out-file",
                      dest = "ofile_name",
                      help = "Output odin file name",
                      metavar = "FILE")
    (opts, args) = parser.parse_args()

    opts.ifile_name = None
    if len(args) > 0:
        opts.ifile_name = args[0]

    if not opts.ifile_name:
        parser.error("No input file specified")
    if not opts.ofile_name:
        parser.error("No output file specified")

    return opts


def usf_read(usf_file):
    """
    Parses the data in a usf file.
    """
    burst_list = []
    pc_rdist_map = {}
    for event in usf_file:
        if isinstance(event, pyusf.Burst):
            burst_list.append([])
        else:
            burst_list[-1].append(event)

            if isinstance(event, pyusf.Sample):
                pc1 = event.begin.pc
                pc2 = event.end.pc
                rdist = event.end.time - event.begin.time - 1
            elif isinstance(event, pyusf.Dangling):
                continue

            if pc_rdist_map.has_key((pc1, pc2)):
                pc_rdist_map[(pc1, pc2)].append(rdist)
            else:
                pc_rdist_map[(pc1, pc2)] = [rdist]

    return burst_list, pc_rdist_map


def odin_write(odin_file, pc1_sdist):
    header = pyodin.Header()
    header.version_major = 1
    header.version_minor = 0
    odin_file.append(header)

    prec_list = []
    for (pc1, pc2), sdist_list in pc1_sdist.items():
        for sdist in set(sdist_list): # Remove duplicates
            prec = pyodin.PerformanceRecord()
            prec.pc1 = pc1
            prec.pc2 = pc2
            prec.stack_distance = sdist
            prec.sample_count = sdist_list.count(sdist)
            prec_list.append(prec)

    perf = pyodin.Performance()
    perf.performance = prec_list

    odin_file.append(perf)

def rdist2sdist_usf(usf_event_list):
    rdist_hist = {}
    for event in usf_event_list:
        if isinstance(event, pyusf.Sample):
            rdist = event.end.time - event.begin.time - 1
        elif isinstance(event, pyusf.Dangling):
            rdist = sys.maxint

        if rdist_hist.has_key(rdist):
            rdist_hist[rdist] += 1
        else:
            rdist_hist[rdist] = rdist

    return lrumodel.lru_sdist(rdist_hist)

def comp_sdist(burst_list):
    """
    Computes a mapping form reuse distance to avarage stack distances.
    """
    rdist2sdist = {}
    for burst in burst_list:
        burst_rdist2sdist = rdist2sdist_usf(burst)
        # Merge the stack distance distribution of the bursts
        for rdist, sdist in burst_rdist2sdist.items():
            if rdist2sdist.has_key(rdist):
                rdist2sdist[rdist].append(sdist)
            else:
                rdist2sdist[rdist] = [sdist]

    # Compute avarage stack distances
    for rdist, sdist_list in rdist2sdist.items():
        rdist2sdist[rdist] = int(round(float(sum(sdist_list)) / len(sdist_list)))

    return rdist2sdist


def comp_pc1_sdist(rdist2sdist, pc1_rdist):
    """
    Computes a mapping from pc1 to a avarage stack distance distribution.
    """
    pc1_sdist = {}
    for (pc1, pc2), rdist_list in pc1_rdist.items():
        sdist_list = []
        for rdist in rdist_list:
            sdist_list.append(rdist2sdist[rdist])
        pc1_sdist[(pc1, pc2)] = sdist_list
    return pc1_sdist


def main():
    args = parse_args()

    try:
        usf_file = pyusf.Usf(args.ifile_name)
    except IOError, e:
        print_and_exit(str(e))

    burst_list, pc1_rdist = usf_read(usf_file)

    rdist_sdist = comp_sdist(burst_list)
    pc1_sdist = comp_pc1_sdist(rdist_sdist, pc1_rdist)

    try:
        odin_file = pyodin.Odin()
        odin_file.create(args.ofile_name)
    except IOError, e:
        print_and_exit(str(e))

    odin_write(odin_file, pc1_sdist)

    usf_file.close()
    odin_file.close()

if __name__ == "__main__":
   main()
