#!/usr/bin/python
import histogram
import missratio

def lru_sdist(rdist_hist, boundary = False):
    rdist_pdf   = histogram.Pdf(rdist_hist)
    rdist_rcdf  = histogram.Cdf_r(rdist_hist)
    rdist_sdist = {}

    for rdist, rcdf in rdist_rcdf:
        if len(rdist_sdist) == 0:
            prev_rdist = rdist
            prev_sdist = rdist
            rdist_sdist[rdist] = rdist
        else:
            if boundary:
                prev_sdist += (rdist - prev_rdist - 1) * rcdf + \
                              rcdf / (1.0 - rdist_pdf[prev_rdist])
            else:
                prev_sdist += (rdist - prev_rdist) * rcdf

            prev_rdist = rdist
            rdist_sdist[rdist] = prev_sdist

    return rdist_sdist

def sdist_hist(rdist_hist_list, filtered_rdist_hist_list, boundary = False):
    sdist_hist = {}

    for hist, filtered_hist in zip(rdist_hist_list, filtered_rdist_hist_list):
        rdist_sdist_map = lru_sdist(hist, boundary)

        for (rdist, count) in filtered_hist.items():
            sdist = int(round(rdist_sdist_map[rdist]))
            sdist_hist[sdist] = sdist_hist.get(sdist, 0) + count

    return sdist_hist

def miss_ratio(rdist_hist_list, filtered_rdist_hist_list, boundary = False):
    if filtered_rdist_hist_list == None:
        filtered_rdist_hist_list = rdist_hist_list

    sdist_hist_items = sdist_hist(rdist_hist_list, filtered_rdist_hist_list,
                                  boundary).items()
    sdist_hist_items.sort(lambda (k0, v0), (k1, v1): cmp(k0, k1))
    
    miss_count  = reduce(lambda y, x: y + sum(x.values()),
                        filtered_rdist_hist_list, 0)

    ref_count   = reduce(lambda y, x: y + sum(x.values()),
                        rdist_hist_list, 0)
    miss_ratio = []
    for sdist, count in sdist_hist_items:
        miss_ratio.append((sdist, float(miss_count) / ref_count))
        miss_count -= count

    return missratio.MissRatio(miss_ratio)

def miss_ratio_range(rdist_hist_list, cache_size_range, boundary = False,
                     filtered_rdist_hist_list = None):
    mr = miss_ratio(rdist_hist_list, filtered_rdist_hist_list,
                    boundary)

    mr_out = []
    for cache_size in cache_size_range:
        mr_out.append((cache_size << 6, mr[cache_size]))
    return missratio.MissRatio(mr_out)



##
## Test cases
##
import sys
import uart.test

class Test(uart.test.TestCase):
    def hist_str(self, hist):
        s = ""
        items = hist.items()
        items.sort(lambda (k1, v1), (k2, v2): cmp(k1, k2))
        for b, c in items:
            s += "%d: %d\n" % (b, c)
        return s

    def parse_file(self, file_name):
        rd_hist = {}
        sd_hist = {}

        file = open(file_name, "r")
        for line in file:
            if line != "\n":
                rd, sd, cnt = map(int, line[:-1].split(","))
                if rd_hist.has_key(rd):
                    rd_hist[rd] += cnt
                else:
                    rd_hist[rd] = cnt
                if sd_hist.has_key(sd):
                    sd_hist[sd] += cnt
                else:
                    sd_hist[sd] = cnt
        file.close()
        return rd_hist, sd_hist

    def do_test(self, file_name):
        rd_hist, sd_hist_ref = self.parse_file(file_name)
        sd_hist = sdist_hist([rd_hist], [rd_hist])
        self.log("rdist_hist:\n" + self.hist_str(rd_hist))
        self.log("sdist_hist_ref:\n" + self.hist_str(sd_hist_ref))
        self.log("sdist_hist:\n" + self.hist_str(sd_hist))
        self.fail_if(sd_hist != sd_hist_ref)

    def test1(self):
        self.do_test("test/lru_test1.txt")

    def test2(self):
        self.do_test("test/lru_test2.txt")

    def test3(self):
        self.do_test("test/lru_test3.txt")

    def test4(self):
        self.do_test("test/lru_test4.txt")


if __name__ == "__main__":
    sys.exit(Test().run())

