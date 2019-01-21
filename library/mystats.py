import random
import math
import json
import matplotlib.pyplot as plt
import numpy as np
import matplotlib
from matplotlib import colors
from matplotlib.ticker import PercentFormatter


class Stats:
    def __init__(self, sequence):
        self.seq = sequence
        self.avg = self.Avg()
        self.var = self.Var()
        self.std = self.StandardDeviation()
        self.max = 0.0
        self.min = 0.0
        if self.seq != []:
            self.max = max(sequence)
            self.min = min(sequence)

    def Avg(self):
        if len(self.seq) <= 0:
            return 0.0
        return float(sum(self.seq)) / float(len(self.seq))

    def Avg2(self):
        if len(self.seq) <= 0:
            return 0.0
        seq = np.power(self.seq, 2)
        return float(sum(seq)) / float(len(seq))

    def Var(self):
        var = self.Avg2() - self.Avg()**2
        if var <= 0:
            return 0.0
        return var

    def StandardDeviation(self):
        return math.sqrt(self.Var())   
