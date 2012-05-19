#!/usr/bin/python
import sys
import pyusf

__author__ = "Andreas Sandberg <andreas.sandberg@it.uu.se>"
__version__ = "$Revision: 774 $"

class NTAFinderError(Exception):
    r"""Base class for all  NTAFinder errors"""
    
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return "Error: %s" % self.message

class NTAFinderFormatError(NTAFinderError):
    r"""File format errors."""

    def __init__(self, message):
        NTAFinderError.__init__(self, message)

class NTAFinderNotImplementedError(NTAFinderError):
    r"""Requested functionallity is not implemented."""

    def __init__(self):
        NTAFinderError.__init__(self,
                                "The requested functionallity is not yet "
                                "implemented.")

class NTACondition:
    r"""Base class for an NTA condition.

    Implementations of an NTA condition should extend this class and
    implement the following methods:
      rdist_follow
      rdist_patch
      rdist_inhibit
      hist_weight
    
    Attributes:
        pcs        - Map between pc1 and a map indexed by pc2 with a reuse
                     distance histogram as its value.
    """

    def __init__(self):
        pass

    def init(self, pcs, global_rdist_hist):
        r"""
        Local init function called by the NTAFinder class when this condition
        is used. Used to initialize structures that depend on data in the
        sample file.
        """
        self.pcs = pcs

    def _rdist_hist_or_func(self, rdist_hist, func):
        r"""
        Creates the logical or of a function, func, applied to every reuse
        distance in a histogram.
        """

        for rdist in rdist_hist.keys():
            if func(rdist):
                return True
        return False

    def _dep_group_or_hist_func(self, pc1, func):
        r"""
        Creates the logical or of a function, func, applied to every 
        forward reuse distance histogram in the dependece group surrounding
        pc1. The dependence group is defined by the follow function.
        """

        # Set of PCs already visited.
        group = set()

        def apply_func(pc1):
            group.add(pc1)

            pc1_info = self.pcs[pc1]
            for pc2_rdists in pc1_info.values():
                if func(pc2_rdists):
                    return True

            for pc2, pc2_rdists in pc1_info.items():
                # Make sure that the PC2 has not been visited before
                # and that there are PC1 samples for the PC1 before
                # checking if NTA attributes should propagate.
                if pc2 not in group and \
                        pc2 in self.pcs and \
                        self.hist_follow(pc2_rdists):
                    if apply_func(pc2):
                        return True

            return False

        return apply_func(pc1)

    def rdist_follow(self, rdist):
        r"""
        Returns True if the presented reuse distance causes the NT
        bit to propagate to PC2, False otherwise. This function defines
        dependence groups in this context.
        """

        raise NTAFinderNotImplementedError()

    def hist_follow(self, rdist_hist):
        return self._rdist_hist_or_func(rdist_hist, self.rdist_follow)

    def rdist_patch(self, rdist):
        r"""
        Returns True if the presented reuse distance is a suitable
        candidate for NTA patching, False otherwise. Note that patching may
        still be inhibited depending on other PCs in the dependence group.
        """

        raise NTAFinderNotImplementedError()

    def hist_patch(self, rdist_hist):
        return self._rdist_hist_or_func(rdist_hist, self.rdist_patch)

    def rdist_inhibit(self, rdist):
        r"""
        Returns True if the presented reuse distance inhibits NTA
        patching of the entire dependence group, False otherwise.
        """

        raise NTAFinderNotImplementedError()

    def hist_inhibit(self, rdist_hist):
        return self._rdist_hist_or_func(rdist_hist, self.rdist_inhibit)


    def hist_weight(self, rdist_hist):
        r"""
        Returns the weight of a specific patch site. Used when
        calculating the importance of a patch site. Should ususally be
        a stack distance.
        """

        raise NTAFinderNotImplementedError()

    def info(self, pc1):
        r"""
        Returns a verbose description of a patch site. Returns None if
        there is no verbose information available.
        """

        return "Weight: %i, Count: %i" % (self.weight(pc1),
                                          sum(self.forward_hist(pc1).values()))


    def is_patch_candidate(self, pc1):
        r"""
        Returns true if a pc1 may be suitable for patching. Patching may still
        be inhibited if inhibit_group is true.
        """

        for pc2_hist in self.pcs[pc1].values():
            if self.hist_patch(pc2_hist):
                return True
        return False

    def inhibit_group(self, pc1):
        r"""
        Checks if the dependence group surrounding pc1 contains any forward
        reuse distance that inhibits patching.
        """

        return self._dep_group_or_hist_func(pc1, self.hist_inhibit)

    def forward_hist(self, pc1):
        r"""
        Create a merged forward reuse distance histogram for PC1.
        """

        fhist = {}

        def add_hist(pc2_hist):
            for rdist, weight in pc2_hist.items():
                fhist[rdist] = fhist.get(rdist, 0) + weight

        for pc2, hist in self.pcs[pc1].items():
            add_hist(hist)

        return fhist

    def weight(self, pc1):
        r"""
        Calculates the "weight" of a patch site. A heigher weight should
        correspond to a higher benefit from patching.

        The current implementation merges all forward reuse distance histograms
        for pc1 and uses the hist_weight function to calculate a weight for the
        merged histogram.
        """

        return self.hist_weight(self.forward_hist(pc1))

    def patch_filter_rdist(self, rdist):
        r"""
        Returns True if the presented reuse distance should be
        included in an instructions forward reuse distance histogram
        after it has been patched.
        """

        raise NTAFinderNotImplementedError()

    def patch_filter_hist(self, rdist_hist):
        r"""
        Filter a forward reuse distance histogram to remove all reuse
        distances that would be removed by patching pc1.
        """

        filtered_rdists = {}
        for rdist, count in rdist_hist.items():
            if self.patch_filter_rdist(rdist):
                filtered_rdists[rdist] = count

        return filtered_rdists
        
        

class NTAFinder:
    r"""
    Finds NTA candidates by analyzing a USF file.

    Attributes:
        pcs         - Map between pc1 and a map indexed by pc2 with a reuse
                      distance histogram as its value.
        rdist_hist  - Map between reuse distances and sample counts.
        nta         - Instance of a condition class that implements the
                      follow/patch/inhibit rules.
        min_samples - Minimum number of samples needed to create a patch site.
        verbose     - True if verbose output is enabled.
        debug       - True if debug output is enabled.
    """

    def __init__(self, file_name, condition, min_samples=1,
                 verbose=False, debug=False):
        self.min_samples = min_samples
        self.verbose = verbose
        self.debug = debug

        usf_file = pyusf.Usf()
        usf_file.open(file_name)

        if usf_file.header.flags & pyusf.USF_FLAG_TRACE:
            raise NTAFinderFormatError("Input is not a sample file.")

        self.pcs = {}
        self.rdist_hist = None

        # TODO: Handle multiple line sizes in sample file.
        for event in usf_file:
            if isinstance(event, pyusf.Burst):
                if self.rdist_hist is None:
                    self.rdist_hist = {}
                else:
                    raise NTAFinderFormatError(
                        "Unsupported file format, more than one burst.")
            elif isinstance(event, pyusf.Sample):
                self.__add_rdist(event.begin, event.end)
            elif isinstance(event, pyusf.Dangling):
                self.__add_rdist(event.begin, None)
            else:
                raise NTAFinderFormatError("Input file contains unexpected events.")


        self.nta = condition
        self.nta.init(self.pcs, self.rdist_hist)

    def __add_rdist(self, begin, end):
        if self.rdist_hist is None:
            raise NTAFinderFormatError(
                "Input contains no burst event before first sample.")

        if end is not None:
            rdist = end.time - begin.time - 1
            pc2 = end.pc
        else:
            rdist = sys.maxint
            pc2 = None

        if not begin.pc in self.pcs:
            self.pcs[begin.pc] = {}

        pc1_rdists = self.pcs[begin.pc]
        if not pc2 in pc1_rdists:
            pc1_rdists[pc2] = {}

        pc1_pc2_rdists = pc1_rdists[pc2]
        pc1_pc2_rdists[rdist] = pc1_pc2_rdists.get(rdist, 0) + 1
        self.rdist_hist[rdist] = self.rdist_hist.get(rdist, 0) + 1


    def _debug(self, msg):
        if self.debug:
            print >> sys.stderr, msg

    def _verbose(self, msg):
        if self.verbose or self.debug:
            print >> sys.stderr, msg

    def _quality_filter(self, pc1):
        return sum(map(lambda x: sum(x.values()),
                       self.pcs[pc1].values())) >= self.min_samples

    def find_patch_sites(self):
        r"""
        Finds patch sites. Returns a list of (PC, weight, info) tuples.
        """
        patch_sites = []

        for (pc1, pc2_rdists) in self.pcs.items():
            qualifies = self._quality_filter(pc1)
            is_candidate = self.nta.is_patch_candidate(pc1)
            has_group_inhibit = self.nta.inhibit_group(pc1)

            self._debug(
                "0x%.4x: [qualifies: %i, is_candidate: %i, has_group_inhibit: %i]" %
                (pc1, qualifies, is_candidate, has_group_inhibit))

            if qualifies and is_candidate and not has_group_inhibit:
                patch_sites.append((pc1, self.nta.weight(pc1), self.nta.info(pc1)))

        return patch_sites

class NTAFinderIterative(NTAFinder):
    r"""
    Finds NTA candidates by analyzing a USF file. Uses an
    iterative approach where the patch sites with the highest weight
    are chosen first and then removed from the histogram.
    """

    def __init__(self, file_name, condition, min_samples=1,
                 verbose=False, debug=False):
        NTAFinder.__init__(self, file_name, condition,
                           min_samples=min_samples,
                           verbose=verbose, debug=debug)

    def _regenerate_global_rdists(self):
        self.rdist_hist = {}
        for pc2_rdists in self.pcs.values():
            for rdists in pc2_rdists.values():
                for rdist, count in rdists.items():
                    self.rdist_hist[rdist] = \
                        self.rdist_hist.get(rdist, 0) + count

    def find_patch_sites(self):
        patch_sites = []
        iteration = 0

        while 1:
            iteration += 1
            new_sites = NTAFinder.find_patch_sites(self)
            if not new_sites:
                break

            patch_pc, patch_weight, patch_info = \
                max(new_sites, key=lambda x: x[1])

            if patch_weight <= 0:
                self._verbose("Iteration %i, max weight %i <= 0. Stopping." %
                              (iteration, patch_weight))
                break

            self._verbose("Iteration %i, %i candidates. "
                          "Choosing 0x%.4x. Weight: %i" %
                          (iteration, len(new_sites),
                           patch_pc, patch_weight))

            self._debug("Samples in histogram: %i" % sum(self.rdist_hist.values()))

            patch_sites.append((patch_pc, patch_weight, patch_info))

            # Remove the patched PC from the histogram
            for pc2, hist in self.pcs[patch_pc].items():
                filtered_hist = self.nta.patch_filter_hist(hist)
                if filtered_hist:
                    self.pcs[patch_pc][pc2] = filtered_hist
                else:
                    del self.pcs[patch_pc][pc2]

            if not self.pcs[patch_pc]:
                del self.pcs[patch_pc]

            self._regenerate_global_rdists()

            # Re-initialize the NTA condition with the new histograms.
            self.nta.init(self.pcs, self.rdist_hist)


        return patch_sites
