#!/usr/bin/python
import sys

from matplotlib import pyplot
from optparse import OptionParser

from uart.hist import Hist
import uart.sample_filter as sample_filter

import pyusf
import lrumodel
import utils

__version__ = "$Revision: 1644 $"

class Conf:
    def __init__(self):
        parser = OptionParser("usage: %prog [OPTIONS...] INFILE")

        parser.add_option("-m", "--marker",
                          type="int", action="append", default=[],
                          dest="marker",
                          help="Add marker.")

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
        self.markers = opts.marker
        self.line_size = opts.line_size

    def help_filters(self, option, opt, value, parser):
        sample_filter.usage()
        sys.exit(0)

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

def generate_sdist_hist(burst_hists):
    hist = {}
    for (rdists, filtered_rdists) in burst_hists:
        r2s = lrumodel.lru_sdist(rdists)
        for (rdist, count) in filtered_rdists.items():
            sdist = r2s[rdist]
            hist[sdist] = hist.get(sdist, 0) + count

    return hist

def main():
    conf = Conf()
    usf_file = open_sample_file(conf.ifile_name, conf.line_size)
    burst_hists = utils.usf_read_events(usf_file,
                                        line_size=conf.line_size,
                                        filter=conf.filter)
    usf_file.close()

    hist = generate_sdist_hist(burst_hists)

    data = hist.items()
    data.sort(key=lambda x: x[0])
    x_values = map(lambda (x, y): x * conf.line_size, data)
    y_values = map(lambda (x, y): y, data)

    if not x_values:
        print >> sys.stderr, "WARNING: Filter result is empty. Nothing to plot."
        sys.exit(0)

    if x_values[0] == 0:
        print >> sys.stderr, "WARNING: Not showing stack distance 0 in hist."
        print >> sys.stderr, "sdist: 0, count: %d" % (y_values[0])
        x_values = x_values[1:]
        y_values = y_values[1:]

    if not x_values:
        print >> sys.stderr, "WARNING: Nothing to plot. Exiting."
        sys.exit(0)

    # plot the histogram
    pyplot.hold(True)
    pyplot.title("Stack distance histogram")
    pyplot.ylabel("Samples")
    pyplot.xlabel("Stack distance (bytes)")
    pyplot.yscale('log', basey = 10)
    pyplot.xscale('log', basex = 2)

    pyplot.bar(x_values, y_values)

    for marker in conf.markers:
        print "Marker: %i" % marker
        pyplot.axvline(marker);

    pyplot.axis([ 1, float(max(x_values)), 1, float(max(y_values)) ])
    pyplot.hold(False)
    pyplot.show()
    
    
if __name__ == "__main__":
    main()

