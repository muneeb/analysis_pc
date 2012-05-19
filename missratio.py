#!/usr/bin/python
from uart.interp import LinearInterp, StepInterp

class MissRatio(StepInterp):
    def __init__(self, points):
        StepInterp.__init__(self, points, True)

    def _getitem__(self, i):

        for c, m in self.points:
            if c == i:
                return m

    def __str__(self):
        s = ""
        for c, m in self.points:
            s += "%d: %f\n" % (c, m)
        return s

class MissRate(LinearInterp):
    def __init__(self, miss_ratio, latancy = 0):
        def cpi(mr):
            return 1.0 + latancy * 0.25 * mr

        points = []
        for (c, mr) in miss_ratio:
            points.append((c, mr / cpi(mr)))
        LinearInterpol.__init__(self, points)
