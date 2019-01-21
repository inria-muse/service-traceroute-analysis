import threading
import time
import os
import json
from threading import Thread
from myutils import *

def InstallSelenium():
    Printer.Print("Installing Selenium")
    os.system("sudo pip install -U selenium")
try:
    from selenium import webdriver
except:
    InstallSelenium()
    from selenium import webdriver
from selenium.webdriver.firefox.options import Options

 


class Video:
    NETFLIX_ACC = "ivan.morandi@studenti.unitn.it"
    NETFLIX_PD = "traceTCPexperiment"
    NETFLIX_LOGIN = "https://www.netflix.com/login"

    TWITCH_POOL = [
        "https://www.twitch.tv",
    ]

    YOUTUBE_POOL = [
        'https://youtu.be/2h7Dy7O2brs?t=1s',
        #'https://www.youtube.com/watch?v=IRfqvsgWBMw?t=1s',
        'https://www.youtube.com/watch?v=uhBBpfk2DWk?t=1s',
        'https://www.youtube.com/watch?v=pM_tOd3fiYA?t=1s',
        'https://www.youtube.com/watch?v=q6VeuE1vDck?t=1s',
        'https://www.youtube.com/watch?v=0wPRrKBNSxY?t=1s',
        'https://www.youtube.com/watch?v=ayklt07vFP8?t=1s',
        'https://www.youtube.com/watch?v=erFK-8FJVnU?t=1s',
        'https://www.youtube.com/watch?v=Dtw2vfKihXA?t=1s',
        'https://www.youtube.com/watch?v=LY1X-_9mamg?t=1s',
        'https://www.youtube.com/watch?v=ZdqSv5_m_Wk?t=1s',
        'https://www.youtube.com/watch?v=R3AKlscrjmQ?t=1s',
        'https://www.youtube.com/watch?v=ICFQS_jpzFY?t=1s',
        'https://www.youtube.com/watch?v=SPLFzEHvqd4?t=1s',
        'https://www.youtube.com/watch?v=Nzbq35hAXRQ?t=1s',
        'https://www.youtube.com/watch?v=wzLaksTl_M0?t=1s',
        'https://www.youtube.com/watch?v=pOPxhBo5Yz0?t=1s',
        'https://www.youtube.com/watch?v=G_XyRZFkFJM?t=1s',
        'https://www.youtube.com/watch?v=ZSoVkaUtTA4?t=1s',
    ]

    NETFLIX_POOL = [
        'https://www.netflix.com/watch/70298735', #edge of tomorrow
        'https://www.netflix.com/watch/70075479', #wanted
        'https://www.netflix.com/watch/70178621',
        'https://www.netflix.com/watch/70259171',
        'https://www.netflix.com/watch/70134402',
        'https://www.netflix.com/watch/70262639',
        'https://www.netflix.com/watch/70140907',
        'https://www.netflix.com/watch/80125409',
        'https://www.netflix.com/watch/70143824',
        'https://www.netflix.com/watch/80083977',
        'https://www.netflix.com/watch/70269488',
        'https://www.netflix.com/watch/60011153',
        'https://www.netflix.com/watch/70143824',
        'https://www.netflix.com/watch/70153404',
        'https://www.netflix.com/watch/70071613',
        'https://www.netflix.com/watch/70213514',
        'https://www.netflix.com/watch/70267241',
        'https://www.netflix.com/watch/693960',
        'https://www.netflix.com/watch/80057281',
        'https://www.netflix.com/watch/20557937',
        'https://www.netflix.com/watch/70178621',
        'https://www.netflix.com/watch/70124805',
        'https://www.netflix.com/watch/80119234',
        'https://www.netflix.com/watch/70108777',
        'https://www.netflix.com/watch/70117305',
        'https://www.netflix.com/watch/70178621'
    ]

    def __init__(self, youtubeIndex=0, netflixIndex=0, twitchIndex=0):
        youtubeIndex = max(youtubeIndex,0)
        youtubeIndex = min(youtubeIndex, self.GetNumberYoutubeVideos()-1)

        netflixIndex = max(netflixIndex, 0)
        netflixIndex = min(netflixIndex, self.GetNumberNetflixVideos()-1)

        twitchIndex = max(twitchIndex, 0)
        twitchIndex = min(twitchIndex, self.GetNumberTwitchVideos()-1)

        self.nextYoutube = youtubeIndex
        self.youtubeMutex = threading.Semaphore()
        self.nextNetflix = netflixIndex
        self.netflixMutex = threading.Semaphore()
        self.nextTwitch = twitchIndex
        self.twitchMutex = threading.Semaphore()

    def NextYoutubeVideo(self):
        self.youtubeMutex.acquire()
        url = Video.YOUTUBE_POOL[self.nextYoutube]
        self.nextYoutube = (self.nextYoutube + 1) % len(self.YOUTUBE_POOL)
        self.youtubeMutex.release()
        return url

    def GetYoutubeVideo(self, i):
        i = max(i,0)
        i = min(i, self.GetNumberYoutubeVideos()-1)

        self.youtubeMutex.acquire()
        url = Video.YOUTUBE_POOL[i]
        self.youtubeMutex.release()

        return url

    def NextTwitchVideo(self):
        self.twitchMutex.acquire()
        url = Video.TWITCH_POOL[self.nextTwitch]
        self.nextTwitch = (self.nextTwitch + 1) % len(self.TWITCH_POOL)
        self.twitchMutex.release()
        return url

    def GetTwitchVideo(self, i):
        i = max(i,0)
        i = min(i, self.GetNumberTwitchVideos()-1)

        self.twitchMutex.acquire()
        url = Video.TWITCH_POOL[i]
        self.twitchMutex.release()

        return url

    def GetNetflixVideo(self, i):
        i = max(i,0)
        i = min(i, self.GetNumberNetflixVideos()-1)

        self.netflixMutex.acquire()
        url = Video.NETFLIX_POOL[i]
        self.netflixMutex.release()

        return url

    def GetYoutubeIndex(self):
        self.youtubeMutex.acquire()
        index = self.nextYoutube
        self.youtubeMutex.release()
        return index

    def GetTwitchIndex(self):
        self.twitchMutex.acquire()
        index = self.nextTwitch
        self.twitchMutex.release()
        return index

    def IsLastYoutubeVideo(self):
        if (self.nextYoutube+1) == len(self.YOUTUBE_POOL):
            return True
        return False

    def NextNetflixVideo(self):
        self.netflixMutex.acquire()
        url = Video.NETFLIX_POOL[self.nextNetflix]
        self.nextNetflix = (self.nextNetflix + 1) % len(self.NETFLIX_POOL)
        self.netflixMutex.release()
        return url


    def GetNetflixIndex(self):
        self.netflixMutex.acquire()
        index = self.nextNetflix
        self.netflixMutex.release()
        return index

    def IsLastNetflixVideo(self):
        if (self.nextNetflix+1) == len(self.NETFLIX_POOL):
            return True
        return False

    def GetNumberYoutubeVideos(self):
        return len(Video.YOUTUBE_POOL)

    def GetNumberNetflixVideos(self):
        return len(Video.NETFLIX_POOL)

    def GetNumberTwitchVideos(self):
        return len(Video.TWITCH_POOL)

class WebPage:
    def __init__(self, filename, index=0):
        Printer.Print("Loading Alexa webpages")
        self.pages = json.load(open(filename))
        self.pagesMutex = threading.Semaphore()

        index = max(0, index)
        index = min(self.GetNumberOfPages()-1, index)
        self.nextPage = index

    def NextPage(self):
        self.pagesMutex.acquire()
        url = self.pages[self.nextPage]['link']
        self.nextPage = (self.nextPage + 1) % len(self.pages)
        self.pagesMutex.release()
        return url
    
    def GetIndex(self):
        self.pagesMutex.acquire()
        index = self.nextPage
        self.pagesMutex.release()
        return index

    def GetNumberOfPages(self):
        self.pagesMutex.acquire()
        nr = len(self.pages)
        self.pagesMutex.release()
        return nr

class Slimerjs:
    def __init__(self):
        self.process = None
        
    def installFlash(self):
        Printer.Print("Installing SlimerJS flash plugin")
        os.system("sudo yum install firefox -y")
        os.system("sudo dnf install http://linuxdownload.adobe.com/adobe-release/adobe-release-x86_64-1.0-1.noarch.rpm -y")
        os.system("sudo dnf install flash-plugin -y")
    
    def runVideo(self, url, timeout):
        timeout *= 1000 #ms
        command = "slimerjs/slimerjs slimerjs/browser.js --headless {} {}".format(url, timeout)
        Printer.Print("Starting SlimerJS to {} with a timeout of {}".format(url, timeout))
        now = time.time()
        #Printer.Print("slimer/node_modules/.bin/slimerjs slimer/browser.js --headless {} {}".format(url, timeout))
        # self.process = subprocess.Popen(["slimer/node_modules/.bin/slimerjs", "slimer/browser.js", "--headless", url, str(timeout)], stdout=subprocess.PIPE, stderr=subprocess.PIPE )
        # stdout, stderr = self.process.communicate()
        Printer.Print(command)
        os.system(command)
        return int(time.time()-now)


class Puppeteer:
    def __init__(self):
        self.process = None
        self.filename = "browser.js"
        self.open = False

        os.system("sudo yum install Xvfb -y")
        # os.system("sudo pkill Xvfb")
        # os.system("Xvfb :99 &")
        # os.system("export DISPLAY=:99")

    
    def runVideo(self, url, timeout, typeVideo, protocol):
        stopTimeout = timeout
        timeout = 1000*timeout #ms
        protocol = protocol.lower()
        if protocol == "udp":
            protocol = "quic"
        command = "cd puppeteer;xvfb-run node {} {} {} {} {}".format(self.filename, url, timeout, typeVideo, protocol)
        now = time.time()
        Printer.Print(command)
        self.open = True
        stopThread = Thread(target = self.stop, args = (2*stopTimeout, ))
        stopThread.start()
        os.system(command);
        self.open = False
        stopThread.join()
        return int(time.time()-now)

    def stop(self,timeout):
        Printer.Print("Killing nodejs after {}s".format(timeout))
        now = time.time()
        while (time.time()-now) < timeout and self.open:
            time.sleep(1)
        
        Printer.Print("Killing nodejs")
        Printer.Print("sudo pkill -f node")
        os.system("sudo pkill -f node")
        Printer.Print("sudo pkill -f chrome")
        os.system("sudo pkill -f chrome")

    def installingNodejs(self):
        Printer.Print("Installing NodeJS")
        os.system("curl --silent --location https://rpm.nodesource.com/setup_8.x | sudo bash -")
        os.system("sudo yum -y install nodejs")
        #Fix libxss error
        os.system("sudo yum install libXScrnSaver pango.x86_64 libXcomposite.x86_64 libXcursor.x86_64 libXdamage.x86_64 libXext.x86_64 libXi.x86_64 libXtst.x86_64 cups-libs.x86_64 libXScrnSaver.x86_64 libXrandr.x86_64 GConf2.x86_64 alsa-lib.x86_64 atk.x86_64 gtk3.x86_64 ipa-gothic-fonts xorg-x11-fonts-100dpi xorg-x11-fonts-75dpi xorg-x11-utils xorg-x11-fonts-cyrillic xorg-x11-fonts-Type1 xorg-x11-fonts-misc -y")

class Chrome:
    def __init__(self):
        self.stopVideo = False

    def stopVideo(self):
        self.stopVideo = False

    def runVideo(self, url, waitingTime, videoType, protocol):
        self.stopVideo = False

        Printer.Print("Getting drivers")
        driver = self.getDriver(protocol.lower()=="quic" or protocol.lower() == "udp")

        Printer.Print("Opening {} {}".format(videoType, url))
        driver.get(url)
        if videoType.lower() == "youtube":
            Printer.Print("Waiting the ADS to finish")
            self.WaitYoutubeADS(driver)
        if videoType.lower() == "netflix":
            if not self.IsLoggedInNetflix(driver):
                self.DoLogInNetflix(driver)
                driver.get(url)

        Printer.Print("Watching {}".format(videoType))

        watchingTime = 0
        for i in range(waitingTime):
            if self.stopVideo:
                Printer.Print("Stopping the video due to end of tracetcp")
                break
            watchingTime += 1
            time.sleep(1)

        driver.close()

        Printer.Print("Video lasted for {}".format(watchingTime))
        return watchingTime
    
    def getDriver(self, UDP):
        options = webdriver.ChromeOptions()
        options.add_argument('--headless')
        options.add_argument('--mute-audio')
        if UDP:
            options.add_argument('--enable-quic')
        options.add_argument('user-data-dir=./chrome')

        # set the window size
        options.add_argument('window-size=1200x600')

        # initialize the driver
        driver = webdriver.Chrome(chrome_options=options)
        
        return driver

    def WaitYoutubeADS(self, driver):
        try:
            #Wait until the div is removed
            while(True):
                driver.find_element_by_xpath("//div[@class='videoAdUi']")
                time.sleep(1)
        except:
            #no ads
            pass
    
    def IsLoggedInNetflix(self, driver):
        try:
            signin = driver.find_element_by_xpath("//a[@class='authLinks']")
            return False
        except:
            return True
    
    def DoLogInNetflix(self, driver):
        driver.get(Video.NETFLIX_LOGIN)

        email = driver.find_element_by_xpath("//input[@id='email']")
        email.send_keys(Video.NETFLIX_ACC)
        pwd = driver.find_element_by_xpath("//input[@id='password']")
        pwd.send_keys(Video.NETFLIX_PD)
        submit = driver.find_element_by_xpath("//button[@class='btn login-button btn-submit btn-small']")
        submit.click()

        Printer.Print("Logged in on netflix")
    
class Browser:
    def __init__(self, osystem, path=""):
        self.osystem = osystem
        self.path = path
        self.stopVideo = False

        self.slimer = Slimerjs()
        self.puppeteer = Puppeteer()
        self.chrome = Chrome()
        
        if osystem == OSystem.FEDORA:
            self.puppeteer.installingNodejs()
            self.slimer.installFlash()
        
    @staticmethod
    def DownloadPageWithoutBrowser(url, filename):
        # command = "sudo {} {} {} > {} 2>&1".format("curl","-i", url, filename)
        command = "{} {}".format("curl", url)
        Printer.Print(command)
        process = subprocess.Popen(['curl', url], stdout=subprocess.PIPE)
        stdout = process.communicate()[0]
        # os.system(command)
        Printer.Print("Page downloaded")

    def RunVideo(self, url, timeout, videoType, protocol):
        protocol = protocol.lower()
        videoType = videoType.lower()

        if self.osystem != OSystem.FEDORA:
            return self.chrome.runVideo(url, timeout, videoType, protocol)
        if videoType == "youtube":
            return self.puppeteer.runVideo(url, timeout, videoType, protocol)
        return self.slimer.runVideo(url, timeout)
        