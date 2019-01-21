import random
import math
import json
import matplotlib.pyplot as plt
import numpy as np
import matplotlib
from matplotlib import colors
from matplotlib.ticker import PercentFormatter
from library.mystats import *


class Plotter:
    @staticmethod
    def Histogram(filename, title, xlabel, ylabel, sequence, binsize=1, xmax=0, ymax=0):
        stats = Stats(sequence)

        if len(sequence) > 0:
            max_seq = max(max(sequence) + 1, 10)
        else:
            max_seq = 10

        dx = binsize
        X  = np.arange(0,max_seq,binsize)

        fig1 = plt.figure()
        ax1 = fig1.add_subplot(111)

        ax1.set_xlabel(xlabel)
        ax1.set_ylabel(ylabel)
        ax1.set_title(title)
        ax1.grid(True)
        if xmax > 0:
            ax1.set_xlim(xmin=0, xmax = min(max_seq, xmax))
        if ymax > 0:
            ax1.set_ylim(ymin=0, ymax = ymax)

        ax1.text(0.79, 0.86, 'Avg: {}\nStDev: {}\nMin: {}\nMax: {}'.format(round(stats.avg,2), round(stats.std,2), round(stats.min,2), round(stats.max,2)), style='italic',
        horizontalalignment='left', verticalalignment='center', transform=ax1.transAxes, bbox={'facecolor':'red', 'alpha':0.5, 'pad':10})

        bins = range(0, max_seq + binsize, binsize)
        n, bins, patches = ax1.hist(sequence, bins=bins)

        for patch in patches:
            patch.set_fc((random.random(), random.random(), random.random()))

        fig1.savefig(filename, dpi=300)
        plt.close()

    @staticmethod
    def PlotXY(filename, title, xlabel, ylabel, xmax, ymax, x, y):
        fig1 = plt.figure()
        ax1 = fig1.add_subplot(111)

        ax1.set_xlabel(xlabel)
        ax1.set_ylabel(ylabel)
        ax1.set_title(title)
        ax1.grid(True)

        if xmax > 0:
            ax1.set_xlim(xmin=0, xmax = xmax)
        if ymax > 0:
            ax1.set_ylim(ymin=0, ymax = ymax)
        
        ax1.plot(x,y, 'ro')

        fig1.savefig(filename, dpi=300, markersize=5)
        plt.close()

    @staticmethod
    def MultiXY(filename, title, xlabel, ylabel, xmax, ymax, x, yarray, colors, labels, markers):
        fig1 = plt.figure()
        ax1 = fig1.add_subplot(111)

        ax1.set_xlabel(xlabel)
        ax1.set_ylabel(ylabel)
        ax1.set_title(title)
        ax1.grid(True)

        if xmax > 0:
            ax1.set_xlim(xmin=0, xmax = xmax)
        if ymax > 0:
            ax1.set_ylim(ymin=0, ymax = ymax)
        
        for i in range(len(yarray)):
            y = yarray[i]
            color = colors[i]
            marker = markers[i]
            label = labels[i]
            ax1.plot(x,y, color=color, marker=marker, label=label)

        ax1.legend(loc="upper right")
        fig1.savefig(filename, dpi=300, markersize=5)
        plt.close()

    @staticmethod
    def MultiScatter(filename, title, xlabel, ylabel, xarray, yarray, colors, labels, markers, store=True, legenPos="lower right", legenOut=False):
        data = {
            'filename':filename,
            'title':title,
            'xlabel':xlabel,
            'ylabel':ylabel,
            'xarray':xarray,
            'yarray':yarray,
            'colors': colors,
            'labels':labels,
            'markers':markers,
        }
        if store:
            json.dump(data, open("{}.json".format(filename), "w"))

        fig1 = plt.figure()
        ax1 = fig1.add_subplot(111)

        ax1.set_xlabel(xlabel)
        ax1.set_ylabel(ylabel)
        ax1.set_title(title)
        ax1.grid(True)

        # if xmax > 0:
        #     ax1.set_xlim(xmin=0, xmax = xmax)
        # if ymax > 0:
        #     ax1.set_ylim(ymin=0, ymax = ymax)
        
        for i in range(len(yarray)):
            y = yarray[i]
            x = xarray[i]
            label = labels[i]
            marker = "*"
            linestyle = ":"
            color = colors[i%len(colors)]
            if markers != []:
                marker = markers[i%len(markers)]
            
            ax1.plot(x,y, markeredgecolor=color, marker=marker, label=label, linestyle='None', markerfacecolor='None')

        if legenOut:
            ax1.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)
        else:
            ax1.legend(loc=legenPos)
        fig1.savefig(filename, dpi=300, markersize=5, bbox_inches="tight", figsize=[7,3])
        plt.close()

    @staticmethod
    def MultiErrorXY(filename, title, xlabel, ylabel, xmax, ymax, x, yarray, yerrors, colors, labels, markers, linestyles=[], store=True, legenPos="lower right", legenOut=False, legenColumn=0, log=False, legenposy=1.1):
        if legenColumn <= 0:
                legenColumn = len(labels)
        data = {
            'filename':filename,
            'title':title,
            'xlabel':xlabel,
            'ylabel':ylabel,
            'x':x,
            'yarray':yarray,
            'yerrors':yerrors,
            'colors': colors,
            'labels':labels,
            'markers':markers,
            'ymax':ymax,
            'xmax':xmax,
            'linestyles':linestyles
        }
        if store:
            json.dump(data, open("{}.json".format(filename), "w"))

        fig1 = plt.figure()
        ax1 = fig1.add_subplot(111)

        ax1.set_xlabel(xlabel)
        ax1.set_ylabel(ylabel)
        #ax1.set_title(title)
        ax1.grid(True)

        if log:
            ax1.set_yscale("symlog")

        if xmax > 0:
            ax1.set_xlim(xmin=0, xmax = xmax)
        if ymax > 0:
            ax1.set_ylim(ymin=0, ymax = ymax)
        
        
        for i in range(len(yarray)):
            y = yarray[i]
            err = yerrors[i]
            label = labels[i]
            marker = "*"
            linestyle = ":"
            color = colors[i%len(colors)]
            if markers != []:
                marker = markers[i%len(markers)]
            if linestyles != []:
                linestyle = linestyles[i%len(linestyles)]
            ax1.errorbar(x,y, yerr=err, color=color, marker=marker, label=label, linestyle=linestyle, fmt='-o', capsize=5, capthick=2)

        if legenOut:
            posy = legenposy + (int(len(labels) / legenColumn) - 1)*0.05
            ax1.legend(loc="upper center", bbox_to_anchor=(0.5, posy), borderaxespad=0, ncol=legenColumn)
        else:
            ax1.legend(loc=legenPos)
        fig1.savefig(filename, dpi=300, markersize=5, bbox_inches="tight", figsize=[7,3])
        plt.close()

    @staticmethod
    def MultiBoxPlot(filename, title, xlabel, ylabel, sequences, colors, labels, store=True, legenPos="lower right", legenOut=False):
        data = {
            'filename':filename,
            'title':title,
            'xlabel':xlabel,
            'ylabel':ylabel,
            'sequences':sequences,
            'colors': colors,
            'labels':labels,
        }
        if store:
            json.dump(data, open("{}.json".format(filename), "w"))

        fig1 = plt.figure()
        ax1 = fig1.add_subplot(111)

        ax1.set_xlabel(xlabel)
        ax1.set_ylabel(ylabel)
        ax1.set_title(title)
        ax1.grid(True)

        
        
        ax1.boxplot(sequences)

        fig1.savefig(filename, dpi=300, markersize=5, bbox_inches="tight", figsize=[7,3])
        plt.close()

    @staticmethod
    def MultipleCDF(filename, title, xlabel, ylabel, sequences, colors, labels, markers = [], addedlines=[], addedx=[], addedcolors=[], addedlabels=[], addedmarkers=[], xmin=0, xmax=0, ymin=None, binsize=1, logscale="", linestyles=[], store=True, legenPos="lower right", legenOut=True, legenColumn=0, legenposy=1.1):
        if legenColumn <= 0:
                legenColumn = len(labels)
        
        cdfs = []
        x_axes = []
        minx = 0
        maxx = 0

        minseq = min(0, xmin)
        maxseq = max(10, xmax)

        data = {
            'filename':filename,
            'title':title,
            'xlabel':xlabel,
            'ylabel':ylabel,
            'sequences':sequences,
            'colors': colors,
            'labels':labels,
            'markers':markers,
            'xmin':xmin,
            'xmax':xmax,
            'binsize':binsize,
            'linestyles':linestyles
        }
        if store:
            json.dump(data, open("{}.json".format(filename), "w"))


        for sequence in sequences:
            if sequence != []:
                minseq = min(min(sequence), minseq)
                maxseq = max(max(sequence), maxseq)
            maxseq = max(maxseq, abs(minseq))
            minx = min(minx, minseq)
            maxx = max(maxx, maxseq)
        

        lendistr = int((maxseq-minseq) / binsize) + 1

        for sequence in sequences:
            distr = [0]*lendistr
   
            for elem in sequence:
                index = int((elem - minseq) / binsize)
                distr[index] += 1

            sumdistr = sum(distr)
            cdf = [0.0]*lendistr
            x = np.arange(minseq, maxseq+1, binsize)

            if sumdistr == 0:
                sumdistr = 1
            cdf[0] = float(distr[0]) / float(sumdistr)
            for i in range(1,lendistr):
                cdf[i] = cdf[i-1] + float(distr[i]) / float(sumdistr)
            cdfs.append(cdf)
            x_axes.append(x)

        cdfs.extend(addedlines)
        colors.extend(addedcolors)
        labels.extend(addedlabels)
        markers.extend(addedmarkers)
        x_axes.extend(addedx)

        print (labels)
        for i in range(len(cdfs)):
            print ("Label {}".format(labels[i]))
            print (cdfs[i])
            print (x_axes[i])

        fig1 = plt.figure()
        ax1 = fig1.add_subplot(111)

        ax1.set_xlabel(xlabel)
        ax1.set_ylabel(ylabel)
        # ax1.set_title(title)
        ax1.set_xlim(xmin=minx, xmax=maxx)
        if ymin != None:
            ax1.set_ylim(ymin=ymin)
        if "x" in logscale:
            ax1.set_xscale("symlog")
        if "y" in logscale:
            ax1.set_yscale("symlog")
        ax1.grid(True,which="both",ls="-")

        # ax1.set_ylim(ymin=0, ymax=1.1)
        if xmax > 0:
            ax1.set_xlim(xmax = xmax)
        if xmin != 0:
            ax1.set_xlim(xmin=xmin)
        #ax1.set_ylim(ymin=0, ymax = 1.1)

        

        
        for i in range(len(cdfs)):
            marker = "*"
            linestyle = ":"
            color = colors[i%len(colors)]
            if markers != []:
                marker = markers[i%len(markers)]
            if linestyles != []:
                linestyle = linestyles[i%len(linestyles)]

            x = []
            y = []
        
            if 'x' not in logscale:
                x = x_axes[i]
                y = cdfs[i]
            else:
                x.append(x_axes[i][0])
                y.append(cdfs[i][0])
                it = 1
                index = 1
                power = 0
                while index < len(x_axes[i]):
                    # print("x[{}] = {} and y[{}] = {}".format(index, x_axes[i][index], index, cdfs[i][index]))
                    x.append(x_axes[i][index])
                    y.append(cdfs[i][index])
                    it += 1
                    if it % 10 == 0:
                        it = 1
                        power += 1
                    index = it * 10**power

            #     print(x_axes[i][:10])

            # print(labels[i])
            # print(y)
            # print(x)
            handler = ax1.plot(x,y, color=color, label=labels[i], marker=marker, linestyle=linestyle, linewidth=2)

        if legenOut:
            posy = legenposy + (int(len(labels) / legenColumn) - 1)*0.05
            ax1.legend(loc="upper center", bbox_to_anchor=(0.5, posy), borderaxespad=0, ncol=legenColumn)
        else:
            ax1.legend(loc=legenPos)

        fig1.savefig(filename, dpi=300, markersize=5, bbox_inches="tight", figsize=[7,3])
        plt.close()

    @staticmethod
    def MultipleDiffCDF(filename, title, xlabel, ylabel, sequences1, sequences2, colors, labels, markers = [], xmin=0, xmax=0, binsize=1,linestyles=[], logscale=False, store=True):
        cdfs = []
        distrs = []
        distr1 = []
        distr2 = []
        x_axes = []
        minx = 0
        maxx = 0

        minseq = 0
        maxseq = 10

        data = {
            'filename':filename,
            'title':title,
            'xlabel':xlabel,
            'ylabel':ylabel,
            'sequences1':sequences1,
            'sequences2':sequences2,
            'colors': colors,
            'labels':labels,
            'markers':markers,
            'xmin':xmin,
            'xmax':xmax,
            'binsize':binsize,
            'linestyles':linestyles
        }
        if store:
            json.dump(data, open("{}.json".format(filename), "w"))

        #sequences = sequences1 + sequences2
        sequences = []
        for i in range(len(sequences1)):
            seq1 = sequences1[i]
            seq1.sort()
            seq1 = seq1[::-1]
            seq2 = sequences2[i]
            seq2.sort()
            seq2 = seq2[::-1]

            seq = [0]*max(len(seq1), len(seq2))

            for j in range(len(seq1)):
                seq[j] = seq1[j]
            for j in range(len(seq2)):
                seq[j] = seq2[j] - seq[j]
            seq.sort()
            
            sequences.append(seq)
        # for seq in sequences1:
        #     seq.sort()
        #     sequences.append(seq)
        #     print seq
            
        # for i in range(len(sequences2)):
        #     seq = sequences2[i]
        #     seq.sort()
        #     print seq
        #     for j in range(len(seq)):
        #         if j >= len(sequences[i]):
        #             sequences[i].append(seq[j])
        #         else:
        #             print "{} - {}".format(sequences[i][j], seq[j])
        #             sequences[i][j] = abs(sequences[i][j] - seq[j])
        #print sequences
        for sequence in sequences:
            if sequence != []:
                minseq = min(min(sequence), minseq)
                maxseq = max(max(sequence), maxseq)
            maxseq = max(maxseq, abs(minseq))
            minx = min(minx, minseq)
            maxx = max(maxx, maxseq)

        x = np.arange(minseq, maxseq+1, binsize)
        lendistr = int((maxseq-minseq) / binsize) + 1

        #cdfs = [[]]*max(len(sequences1), len(sequences2))
        # distrs = [[]]*max(len(sequences1), len(sequences2))
        # for i in range(len(distrs)):
        #     distrs[i] = [0.0]*lendistr

        for sequence in sequences:
            distr = [0]*lendistr
            for elem in sequence:
                index = int((elem - minseq) / binsize)
                distr[index] += 1

            sumdistr = sum(distr)
            cdf = [0.0]*lendistr
            cdf[0] = float(distr[0]) / float(sumdistr)
            for i in range(1,lendistr):
                cdf[i] = cdf[i-1] + float(distr[i]) / float(sumdistr)
            cdfs.append(cdf)
            

        fig1 = plt.figure()
        ax1 = fig1.add_subplot(111)

        ax1.set_xlabel(xlabel)
        ax1.set_ylabel(ylabel)
        #ax1.set_title(title)
        ax1.set_xlim(xmin=minx, xmax=maxx)
        if logscale:
            ax1.set_xscale("log")
        ax1.grid(True,which="both",ls="-")

        if xmax > 0 and xmax < maxx:
            ax1.set_xlim(xmax = xmax)
        if xmin != 0:
            ax1.set_xlim(xmin=xmin)
        #ax1.set_ylim(ymin=0, ymax = 1.1)
        for i in range(len(cdfs)):
            marker = "."
            linestyle = ":"
            color = colors[i%len(colors)]
            if markers != []:
                marker = markers[i%len(markers)]
            if linestyles != []:
                linestyle = linestyles[i%len(linestyles)]
            handler = ax1.plot(x,cdfs[i], color=color, label=labels[i], marker=marker, linewidth=2, linestyle=linestyle)
        ax1.legend(loc="lower right")
        fig1.savefig(filename, dpi=300, markersize=5, bbox_inches="tight", figsize=[7,3])
        plt.close()

    @staticmethod
    def Cdf(filename, title, xlabel, ylabel, xmax, binsize, sequence):
        minseq = min(sequence)
        maxseq = max(max(sequence), 10)
        maxseq = max(maxseq, abs(minseq))
        lendistr = int((maxseq-minseq) / binsize) + 1

        distr = [0]*lendistr

        for elem in sequence:
            index = int((elem - minseq) / binsize)
            distr[index] += 1

        sumdistr = sum(distr)
        cdf = [0.0]*lendistr
        x = np.arange(minseq, maxseq+1, binsize)

        cdf[0] = float(distr[0]) / float(sumdistr)
        for i in range(1,lendistr):
            cdf[i] = cdf[i-1] + float(distr[i]) / float(sumdistr)

        fig1 = plt.figure()
        ax1 = fig1.add_subplot(111)

        ax1.set_xlabel(xlabel)
        ax1.set_ylabel(ylabel)
        ax1.set_title(title)
        ax1.set_xlim(xmin=minseq-10, xmax=max(maxseq, abs(minseq)))
        ax1.grid(True)

        if xmax > 0:
            ax1.set_xlim(xmin=0, xmax = xmax)
        ax1.set_ylim(ymin=0, ymax = 1.1)
        
        ax1.plot(x,cdf, 'r--')
        ax1.legend(loc="lower right")

        fig1.savefig(filename, dpi=300, markersize=5)
        plt.close()
    
    @staticmethod
    def Pie(filename, title, labels, percentage):
        fig1 = plt.figure()
        ax1 = fig1.add_subplot(111)

        ax1.set_title(title)

        ax1.pie(percentage, labels=labels)

        fig1.savefig(filename, dpi=300, markersize=5)
        plt.close()

    @staticmethod
    def HorizontalBar(filename, title, xlabel, labels, sequence, xmin=0, xmax=1):
        for i in range(len(sequence)-1):
            maxindex = i
            for j in range(i, len(sequence)):
                if sequence[j] < sequence[maxindex]:
                    maxindex = j

            if i != maxindex:
                sequence[maxindex], sequence[i] = sequence[i], sequence[maxindex]
                labels[maxindex], labels[i] = labels[i], labels[maxindex]

        fig1 = plt.figure()
        ax1 = fig1.add_subplot(111)

        ax1.set_title(title)

        y_pos = np.arange(len(labels))
        ax1.barh(y_pos, sequence, align='center', color='blue', ecolor="black")
        ax1.set_yticks(y_pos)
        ax1.set_yticklabels(labels)
        ax1.set_xlabel(xlabel)
        
        ax1.set_xlim(xmin=xmin, xmax=xmax)

        plt.tight_layout()
        fig1.savefig(filename, dpi=300, markersize=5)
        plt.close()