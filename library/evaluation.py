from browser import *
from myutils import *
import argparse
import signal
import sys
#Script idea
#for each video in the pool
# 1 - avvio tcpdump
# 2 - avvio tracetcp
# 3 - avvio il download della pagina / video
# 4 - aspetto la fine del download o 8 minuti
# 5 - aspetto che finisca tracetcp
# 6 - paris-traceroute (i vari esperimenti)
# 7 - chiudo tcpdump
osystem = OSystem.MAC
browserType = Browser.CHROME
waitingTime = 480 #seconds (8 minutes)
filename_format = "{}_{}_{}.{}.{}"

tracetcpCommand = ""

#sudo python evaluation.py --iface eth0 --tracetcp ./tracetcpevaluation --experiment pages --os fedora --alexa alexa.json > script.log 2>&1 &
#RPI
#sudo python evaluation.py --iface eth0 --tracetcp /home/pi/go/src/tracetcp/cmd/tracetcpevaluation/tracetcpevaluation --experiment video --os ubuntu --browser firefox --browserpath /usr/bin/geckodriver --display yes --alexa alexa.json
"""
    Packets to be installed for paris-traceroute:
    git
    build-essential
    autotools-dev
    automake
    libtool
    m4

"""
def RunWebPages(iface, protocol, url, browser, browserCallback, service, index, iteration, tracetcp, parisTraceroute, tcpdump, filename_format):
    tracetcpTimeout = 60
    tracetcp_file = filename_format.format("tracetcp",service, index,iteration,"log")
    tracetcp_noprobes_file = filename_format.format("tracetcp_noprobes",service, index,iteration, "log")
    traceroute_file = filename_format.format("paristraceroute",service, index,iteration,"log")
    tcpdump_file = filename_format.format("tcpdump", service, index,iteration, "pcap")
    tcpdump_paris_file = filename_format.format("tcpdump_paris", service, index,iteration, "pcap")
    tcpdump_notrace_file = filename_format.format("tcpdump_notrace", service, index,iteration, "pcap")
    curl_file_trace = filename_format.format("curl_trace", service, index,iteration, "log")
    curl_file_notrace = filename_format.format("curl_notrace", service, index,iteration, "log")

    #Start asynch listener on the tracetcp file
    tracetcp.ListenerAsynch(tracetcp_file, parisTraceroute, protocol, callback)

    #Start tcpdump asynch
    tcpdump.StartAsynch(iface, tcpdump_file)

    #Start tracetcp asynch
    tracetcp.RunAsynch(tracetcp_file, tracetcpTimeout)
    
    #Download the webpage
    browserCallback(url, curl_file_trace)

    #Kill tracetcp
    #tracetcp.Kill()
    #Wait the end of the thread
    tracetcp.WaitThread()
    #Wait the listener to end
    tracetcp.WaitListener()

    #Allow TCPDump to get all packets 
    Printer.Print("Waiting 1 second for TCPDump")
    time.sleep(1)

    #Kill TCP Dump
    tcpdump.Kill()
    #Wait the thread
    tcpdump.WaitThread()

    time.sleep(5)

    ########################################################################

    Printer.Print("Starting paris-traceroute")

    #Start tcpdump asynch
    tcpdump.StartAsynch(iface, tcpdump_paris_file)

    #Start paris-traceroute to all destinations
    parisTraceroute.RunQueue()
    #Wait the end of all paris traceroute
    # parisTraceroute.WaitAllThreads()
    #Store paris traceroute values
    parisTraceroute.ToFile(traceroute_file)
    #Clear paris traceroute
    parisTraceroute.Clear()

    #Kill TCP Dump
    tcpdump.Kill()
    #Wait the thread
    tcpdump.WaitThread()

    ########################################################################

    #Wait 2 min before starting again the video
    Printer.Print("Waiting 30 seconds before downloading the webpage without tracetcp")
    time.sleep(30)

    #Start tcpdump asynch
    tcpdump.StartAsynch(iface, tcpdump_notrace_file)

    #Watch the video
    browserCallback(url, curl_file_notrace)

    #Allow TCPDump to get all packets 
    Printer.Print("Waiting 1 second for TCPDump")
    time.sleep(1)

    #Kill TCP Dump
    tcpdump.Kill()

    Printer.Print("Waiting 30 seconds before starting the next video")
    time.sleep(30)


def RunVideo(iface, protocol, url, browser, browserCallback, service, index, iteration, tracetcp, parisTraceroute, tcpdump, filename_format):
    tracetcpTimeout = 90
    tracetcp_file = filename_format.format("tracetcp",service, index,iteration,"log")
    tracetcp_noprobes_file = filename_format.format("tracetcp_noprobes",service, index,iteration, "log")
    traceroute_file = filename_format.format("paristraceroute",service, index,iteration,"log")
    tcpdump_file = filename_format.format("tcpdump", service, index,iteration, "pcap")
    tcpdump_paris_file = filename_format.format("tcpdump_paris", service, index,iteration, "pcap")
    tcpdump_notrace_file = filename_format.format("tcpdump_notrace", service, index,iteration, "pcap")

    #Start asynch listener on the tracetcp file
    tracetcp.ListenerAsynch(tracetcp_file, parisTraceroute, protocol, callback)

    #Start tcpdump asynch
    tcpdump.StartAsynch(iface, tcpdump_file)

    #Start tracetcp asynch
    tracetcp.RunAsynch(tracetcp_file, tracetcpTimeout, browser.StopVideo)
    
    #Watch the video
    watchingTime = browserCallback(url, waitingTime)

    #Kill tracetcp
    #tracetcp.Kill()
    #Wait the end of the thread
    tracetcp.WaitThread()
    #Wait the listener to end
    tracetcp.WaitListener()


    #Allow TCPDump to get all packets 
    Printer.Print("Waiting 1 second for TCPDump")
    time.sleep(1)

    #Kill TCP Dump
    tcpdump.Kill()
    #Wait the thread
    tcpdump.WaitThread()

    time.sleep(5)

    ########################################################################

    Printer.Print("Starting paris-traceroute")

    #Start tcpdump asynch
    tcpdump.StartAsynch(iface, tcpdump_paris_file)

    #Start paris-traceroute to all destinations
    parisTraceroute.RunQueue()
    #Wait the end of all paris traceroute
    # parisTraceroute.WaitAllThreads()
    #Store paris traceroute values
    parisTraceroute.ToFile(traceroute_file)
    #Clear paris traceroute
    parisTraceroute.Clear()

    #Kill TCP Dump
    tcpdump.Kill()
    #Wait the thread
    tcpdump.WaitThread()

    ########################################################################

    #Wait 2 min before starting again the video
    Printer.Print("Waiting 30 seconds before starting the video without tracetcp")
    time.sleep(30)

    #Start tcpdump asynch
    tcpdump.StartAsynch(iface, tcpdump_notrace_file)

    #Watch the video
    browserCallback(url, watchingTime)

    #Allow TCPDump to get all packets 
    Printer.Print("Waiting 1 second for TCPDump")
    time.sleep(1)

    #Kill TCP Dump
    tcpdump.Kill()

    Printer.Print("Waiting 30 seconds before starting the next video")
    time.sleep(30)

def callback(traceroute, destination, srcport, dstport, protocol):
    Printer.Print("Adding {} to paris-traceroute queue".format(destination))
    traceroute.Enqueue(destination)
    #traceroute.RunAsynchAllProtocols(destination, srcport, dstport)
    # traceroute.RunAsynch(destination, protocol="tcp")
    # traceroute.RunAsynch(destination)
    # traceroute.RunAsynch(destination, srcport, dstport, "udp")
    # traceroute.RunAsynch(destination, srcport, dstport, "icmp")

def main(tracetcp_path, iface, iterations, firstIndex, lastIndex, osystem, browserType, browserpath, waitingTime, protocol, alexaFile, folder, startNetflix, startYoutube, startPages):
    global filename_format
    br = None
    if startNetflix or startYoutube: 
        br = Browser(osystem, browserType, path=browserpath)
        video = Video(firstIndex, firstIndex)
    if startPages:
        webpages = WebPage(alexaFile, firstIndex)
    tracetcp = TraceTCP(tracetcp_path, iface)
    tracetcp_noprobes = TraceTCP(tracetcp_path, iface)
    tracetcp_noprobes.SetParameters(sendProbes=False)
    parisTraceroute = ParisTraceroute(osystem)
    tcpdump = TCPDump()
    
    if folder[-1] != '/':
        folder = folder + "/"
    path = folder + filename_format

    Printer.Print("Starting and ending index: {} to {}".format(firstIndex, lastIndex))

    for iteration in range(int(iterations)):
        if startYoutube:
            for i in range(max(0, firstIndex), min(lastIndex, video.GetNumberYoutubeVideos())):
                url = video.NextYoutubeVideo()
                RunVideo(iface, protocol, url, br, br.WatchYoutube, "youtube", video.GetYoutubeIndex(),iteration, tracetcp, parisTraceroute, tcpdump, path)
        if startNetflix:
            for i in range(max(0, firstIndex), min(lastIndex, video.GetNumberNetflixVideos())):
                url = video.NextNetflixVideo()
                RunVideo(iface, protocol, url, br, br.WatchNetflix, "netflix", video.GetNetflixIndex(),iteration, tracetcp, parisTraceroute, tcpdump, path)
        if startPages:
            for i in range(max(0, firstIndex), min(lastIndex, webpages.GetNumberOfPages())):
                url = webpages.NextPage()
                tracetcp.SetParameters(sendingAlgorithm=TraceTCP.ALL, interIterationTime=5, interProbeTime=5)
                RunWebPages(iface, protocol, url, br, Browser.DownloadPageWithoutBrowser, "webpage", webpages.GetIndex(),iteration, tracetcp, parisTraceroute, tcpdump, path)

def signal_term_handler(signal, frame):
    global tracetcpCommand

    # process = subprocess.Popen(['sudo', 'pkill','-f',"firefox"], stdout=subprocess.PIPE)
    # stdout = process.communicate()[0]

    # process = subprocess.Popen(['sudo', 'pkill','-f',"chrome"], stdout=subprocess.PIPE)
    # stdout = process.communicate()[0]

    # process = subprocess.Popen(['sudo', 'pkill','-f',"geckodriver"], stdout=subprocess.PIPE)
    # stdout = process.communicate()[0]

    # process = subprocess.Popen(['sudo', 'pkill','-f',"chromedriver"], stdout=subprocess.PIPE)
    # stdout = process.communicate()[0]

    # process = subprocess.Popen(['sudo', 'pkill','-f',"tcpdump"], stdout=subprocess.PIPE)
    # stdout = process.communicate()[0]

    # if '/' in tracetcpCommand:
    #     tracetcpCommand = tracetcpCommand[tracetcpCommand.rindex("/")+1:]

    # process = subprocess.Popen(['sudo', 'pkill','-f',tracetcpCommand], stdout=subprocess.PIPE)
    # stdout = process.communicate()[0]

    exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Run script to study the behaviour and performance of TraceTCP compared to Paris-Traceroute')
    parser.add_argument('--tracetcp', default="~/go/src/tracetcp/cmd/tracetcpevaluation/tracetcpevaluation",
                        help='Path position to tracetcp tool')
    parser.add_argument('--iface', default="eth0",
                        help='Interface of the device. Default eth0')
    parser.add_argument('--it', default="1",
                        help='Number of iterations')
    parser.add_argument('--experiment', default="all",
                        help='Specify the goal of the experiment: all, video, netflix, youtube, pages')
    parser.add_argument('--os', default="mac",
                        help='Operative System of the device. Possible values: "mac", "ubuntu", "fedora". Default: mac')
    parser.add_argument('--browser', default="chrome",
                        help='Browser to use for downloading webpages and videos. Possible values: "chrome", "firefox". Default: chrome')
    parser.add_argument('--browserpath', default="",
                        help='Path for browser drivers')
    parser.add_argument('--w', default=480,
                        help='Waiting time for each video in seconds. Default: 480 seconds')
    parser.add_argument('--p', default="tcp",
                        help='Protocol to use for paris traceroute. Possible values: "icmp", "udp", "tcp". Default: tcp')
    parser.add_argument('--alexa',
                        help='Position of the json file containing all destinations obtained from Alexa')
    parser.add_argument("--results", default="results",
                        help="Path where the script will save all the logs")
    parser.add_argument("--display", default="no", help="Start a fake display  in the case of a missing display environment")
    parser.add_argument("--firstIndex", default=0, help="Start index to download data [included]")
    parser.add_argument("--lastIndex", default=sys.maxint, help="Last index to download data [not included]")

    res = parser.parse_args()

    waitingTime = int(res.w)
    iface = res.iface

    netflixFlag = False
    youtubeFlag = False
    pagesFlag = False

    firstIndex = 0
    lastIndex = sys.maxint

    try:
        firstIndex = int(res.firstIndex)
        lastIndex = int(res.lastIndex)
    except:
        Printer.Print("Indexes are not numbers")
        exit(1)

    if res.experiment.lower() == "all":
        netflixFlag = True
        youtubeFlag = True
        pagesFlag = True
    elif res.experiment.lower() == "video":
        netflixFlag = True
        youtubeFlag = True
    elif res.experiment.lower() == "youtube":
        youtubeFlag = True
    elif res.experiment.lower() == "netflix":
        netflixFlag = True
    elif res.experiment.lower() == "pages":
        pagesFlag = True
    else:
        Printer.Print("Error, wrong experiment goal")
        exit(1)

    if res.os.lower() == OSystem.UBUNTU:
        osystem = OSystem.UBUNTU
    elif res.os.lower() == OSystem.MAC:
        osystem = OSystem.MAC
    elif res.os.lower() == OSystem.FEDORA:
        osystem = OSystem.FEDORA
    else:
        Printer.Print("Error, wrong OS")
        exit(1)
    if res.it < 1:
        Printer.Print("Error, zero or negative number of iterations")
        exit(1)
    if res.browser.lower() == Browser.FIREFOX:
        browserType = Browser.FIREFOX
    elif res.browser.lower() == Browser.CHROME:
        browserType = Browser.CHROME
    else:
        Printer.Print("Error, wrong browser")
        exit(1)

    display = None
    if res.display.lower().strip() == "yes":
        from pyvirtualdisplay import Display
        display = Display(visible=0, size=(800, 600))
        display.start()

    Printer.Print("Setting up SIGNINT handler")
    signal.signal(signal.SIGINT, signal_term_handler)
    os.system("rm -f {}/*".format(res.results))
    os.system("rm -rf chrome")
    os.system("mkdir {}".format(res.results))
    os.system("rm -rf {}/*".format(res.results))

    # Printer.Print("Install PIP")
    # if osystem == OSystem.UBUNTU:
    #     os.system("sudo apt install python-pip -y")
    # elif osystem == OSystem.FEDORA:
    #     os.system("sudo yum upgrade python-setuptools -y")
    #     os.system("sudo yum install python-pip python-wheel -y")
    tracetcpCommand = res.tracetcp
    main(res.tracetcp, iface, res.it, firstIndex, lastIndex, osystem, browserType,res.browserpath, waitingTime, res.p, res.alexa, res.results, netflixFlag, youtubeFlag, pagesFlag)
    
    if display != None:
        display.stop()


