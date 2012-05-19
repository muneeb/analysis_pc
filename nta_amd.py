#!/usr/bin/python
import sys
import getopt
import StringIO

import nta
import lrumodel

__author__ = "Andreas Sandberg <andreas.sandberg@it.uu.se>"
__version__ = "$Revision: 803 $"

class NTAConditionLRU_AMD(nta.NTACondition):
    r"""
    Class containing conditions for doing NTA analysis using LRU replacement.

    Attributes:
        r2s         - Map between reuse distances and stack distances.
        l1_lower    - Lower threshold for l1 cache (lines), used when deciding
                      whether a cache access hits l1 or l2.
        l1_upper    - Upper threshold for l1 cache (lines), used when
                      determining whether the NTA status is propagated or not.
        patch_size  - Patch size in lines
    """

    def __init__(self, line_size, l1l_size, l1u_size, patch_size):
        self.l1_lower = l1l_size / line_size
        self.l1_upper = l1u_size / line_size
        self.patch_size = patch_size / line_size

        nta.NTACondition.__init__(self)

    def init(self, pcs, global_rdist_hist):
        self.r2s = lrumodel.lru_sdist(global_rdist_hist)

        nta.NTACondition.init(self, pcs, global_rdist_hist)

    def rdist_follow(self, rdist):
        return self.r2s[rdist] < self.l1_upper

    def rdist_patch(self, rdist):
        return self.r2s[rdist] >= self.patch_size

    def rdist_inhibit(self, rdist):
        sdist = self.r2s[rdist]
        return sdist >= self.l1_lower and sdist < self.patch_size

    def hist_weight(self, rdist_hist):
        # Calculate the weighted average of the histogram excluding
        # rdists that would hit in the cache. We also ignore danglings
        # for now.
        w = 0.0
        s = 0
        for rdist, count in rdist_hist.items():
            if rdist != sys.maxint and \
                    self.r2s[rdist] >= self.patch_size:
                w += self.r2s[rdist] * count
                s += count

        return w / s if s != 0 else 0

    def patch_filter_rdist(self, rdist):
        # TODO: Is this the right limit?
        return self.r2s[rdist] < self.l1_upper

nta_finder_modes = {
    "simple" : nta.NTAFinder,
    "iterative" : nta.NTAFinderIterative
}

class Conf():
    def __init__(self):
        self.infile = None
        self.line_size = 64
        self.cache_size = (64 + 512 + 6 * 1024)  * 1024
        self.l1u_size = 64 * 1024 << 1
        self.l1l_size = 64 * 1024 >> 1
        self.min_samples = 50

        self.mode = "simple"

        self.verbose = False
        self.debug = False

    def __str__(self):
        out = StringIO.StringIO()
        print >> out, "# Parameters:"
        for param, value in self.__dict__.items():
            print >> out, "#  %s: %s" % (param, str(value))

        return out.getvalue()[:-1]

    def usage(self, error=None, file=sys.stdout):
        print >> file, \
"""Usage: nta_amd.py [OPTION...] USF_FILE
Outputs a patch file that limits an applications cache usage to a predetermined
partition using non-temporal patching.

  -p SIZE                    Partition size (default: %i)
  -c SIZE                    Lower L1 size (default: %i)
  -C SIZE                    Upper L1 size (default: %i)
  -l SIZE                    Line size (default: %i)

  -s THRESHOLD               Minimum number of samples (default: %i)

  -m MODE                    Mode of operation (default: %s)

  -v                         Verbose output
  -d                         Debug output
  -h                         Print usage""" % (self.cache_size,
                                               self.l1l_size,
                                               self.l1u_size,
                                               self.line_size,
                                               self.min_samples,
                                               self.mode)
        if error != None:
            print >> file
            print >> file, "Error: %s" % error

    def parse(self):
        short_opts = 'p:c:C:l:s:m:vdh'
        long_opts  = [ ]

        try:
            opts, args = getopt.getopt(sys.argv[1:], short_opts, long_opts)
        except getopt.GetoptError, e:
            self.usage(error=str(e), file=sys.stderr)
            sys.exit(1)

        for o, a in opts:
            if o in ('-p'):
                self.cache_size = int(a)
            elif o in ('-c'):
                self.l1l_size = int(a)
            elif o in ('-C'):
                self.l1u_size = int(a)
            elif o in ('-l'):
                self.line_size = int(a)

            elif o in ('-s'):
                self.min_samples = int(a)

            elif o in ('-m'):
                if a not in nta_finder_modes:
                    self.usage("Illegal NTA finder mode.", file=sys.stderr)
                    sys.exit(1)

                self.mode = a

            elif o in ('-v'):
                self.verbose = True
            elif o in ('-d'):
                self.debug  = True
                self.verbose = True
            elif o in ('-h'):
                self.usage()
                sys.exit(0);

            else:
                assert(False)


        if not args:
            self.usage(error="No input file specified.",
                       file=sys.stderr)
            sys.exit(1)
        elif len(args) > 1:
            self.usage(error="Only one input file may be specified.",
                       file=sys.stderr)
            sys.exit(1)

        self.infile = args[0]


def main():
    conf = Conf()
    conf.parse()

    nta_condition = NTAConditionLRU_AMD(conf.line_size, conf.l1l_size,
                                        conf.l1u_size, conf.cache_size)
    nta_finder = nta_finder_modes[conf.mode](
        conf.infile, nta_condition,
        min_samples=conf.min_samples,
        verbose=conf.verbose,
        debug=conf.debug)

    if conf.verbose:
        print "# Command line: %s" % str(sys.argv)
        print str(conf)
        print "#"
        print "# nta_amd.py revision: %s" % __version__
        print "# nta.py revision: %s" % nta.__version__
        print "#"

    patches = nta_finder.find_patch_sites()
    patches.sort(key=lambda x: x[1], reverse=True)
    for addr, weight, info in patches:
        if conf.verbose and info:
            print "# %s" % info

        print "0x%.4x:nta" % addr


if __name__ == '__main__':
    sys.exit(main())
