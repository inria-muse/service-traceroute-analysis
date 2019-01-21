from selenium import webdriver
import time

print "Getting driver..."
driver = webdriver.PhantomJS(executable_path="slimerjs")
print "Getting web page..."
driver.get("https://www.youtube.com/watch?v=uhBBpfk2DWk?t=1s")
print "Going to sleep..."
time.sleep(10)
print "Taking a nice pic..."
driver.get_screenshot_as_file('screenshot.png') 
print "Leaving, byebye..."
driver.quit()