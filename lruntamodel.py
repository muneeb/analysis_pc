#!/usr/bin/python
import histogram
import missratio

import pyusf

import sys

__version__ = "$Revision: 887 $"

RDIST_DANGLING = sys.maxint
SDIST_DANGLING = sys.maxint

class BurstInfo:
    def __init__(self, filter, patch_list):
        self.rdist_hist = {}
        self.frdist_hist = {}
        self.num_nta = 0
        self.num_samples = 0
        self.filter = filter
        self.patch_list = patch_list

    def add_event(self, event):
        if isinstance(event, pyusf.Sample):
            rdist = event.end.time - event.begin.time - 1
        elif isinstance(event, pyusf.Dangling):
            rdist = RDIST_DANGLING
        else:
            assert(False)

        is_pc1_nta = event.begin.pc in self.patch_list
        self.num_samples += 1

        # HACK HACK HACK
        if not is_pc1_nta or rdist <= 1024:
            self.rdist_hist[rdist] = self.rdist_hist.get(rdist, 0) + 1
        else:
            self.num_nta += 1
            rdist = RDIST_DANGLING

        if self.filter(event.begin,
                       event.end if isinstance(event, pyusf.Sample) else None,
                       rdist):
            self.frdist_hist[rdist] = self.frdist_hist.get(rdist, 0) + 1

    def nta_ratio(self):
        return float(self.num_nta) / self.num_samples

class LRUNTAModel:
    def __init__(self, usf_file, line_size, filter, patch_list):
        burst_info = []
        for event in usf_file:
            if isinstance(event, pyusf.Burst):
                burst_info.append(BurstInfo(filter, patch_list))
            elif isinstance(event, pyusf.Sample) or \
                    isinstance(event, pyusf.Dangling):
                assert(burst_info)
                if (1 << event.line_size) != line_size:
                    continue
                burst_info[-1].add_event(event)
            else:
                assert(False)

        if len(burst_info) > 1:
            print >> sys.stderr, "Warning: LRU NTA analysis will only be " + \
                "performed for the first burst."

        self.burst_info = burst_info
        self.rdist_hist = burst_info[0].rdist_hist
        self.rdist2sdist = self._calc_rdist2sdist(burst_info[0])


    def _calc_rdist2sdist(self, burst_info):
        rdist_rcdf = histogram.Cdf_r(burst_info.rdist_hist)
        rdist_sdist = {}

        for unscaled_rdist, rcdf in rdist_rcdf:
            rdist = unscaled_rdist * (1 - burst_info.nta_ratio())
            if len(rdist_sdist) == 0:
                prev_rdist = rdist
                prev_sdist = rdist
                rdist_sdist[rdist] = rdist
            else:
                prev_sdist += (rdist - prev_rdist) * rcdf
                prev_rdist = rdist
                rdist_sdist[rdist] = prev_sdist

        return rdist_sdist

    def sdist_hist(self):
        burst_info = self.burst_info[0]
        sdist_hist = {}

        for (unscaled_rdist, count) in burst_info.frdist_hist.items():
            # If the sample file lacks dangling samples, but has NTA
            # samples, things would break unless we have the following
            # test. I.e. there would be no entry for RDIST_DANGLING in
            # rdist2sdist.
            if unscaled_rdist == RDIST_DANGLING:
                sdist = SDIST_DANGLING
            else:
                rdist = unscaled_rdist * (1 - burst_info.nta_ratio())
                sdist = int(round(self.rdist2sdist[rdist]))

            sdist_hist[sdist] = sdist_hist.get(sdist, 0) + count

        return sdist_hist

    def miss_ratio(self, sdist_hist, global_ref=False):
        burst_info = self.burst_info[0]

        sdist_hist_items = sdist_hist.items()
        sdist_hist_items.sort(lambda (k0, v0), (k1, v1): cmp(k0, k1))

        miss_count = sum(burst_info.frdist_hist.values())
        ref_count = \
            sum(burst_info.rdist_hist.values()) if global_ref else miss_count
        miss_ratio = []
        for sdist, count in sdist_hist_items:
            miss_ratio.append((sdist, float(miss_count) / ref_count))
            miss_count -= count

        return missratio.MissRatio(miss_ratio)

    def miss_ratio_range(self, cache_size_range):
        sdist_hist = self.sdist_hist()

        mr = self.miss_ratio(sdist_hist)
        mr_out = []
        for cache_size in cache_size_range:
            mr_out.append((cache_size, mr[cache_size]))
        return missratio.MissRatio(mr_out)
