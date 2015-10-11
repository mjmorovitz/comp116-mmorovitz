All parts of this project were successfully implemented.
I discussed this project with Ming Chow. He ran my alarm file on his VM to test it.
I spent approximately 3 hours on this project.

While this alarm does a decent job at detecting some of the basic scans, there are several issues with it. Firstly, it can easily give false positives. For example, the alert for an Nmap scan is triggered by the word NMAP. This means that any mention of Nmap , even if it is not an actual Nmap scan will trigger a Nmap scan alert.
Thus, while the scan does a reasonably good job detecting obvious and simple scans and data it fails to detect anything less obvious. For some scans, t can check flags which is a bit more convincing, however, scnas such as general nmap, nikto , masscan, or phpmyadmin, it simply searches for the phrase.

If I had more time, I would be interested in improving how I detect nmap scans. Right now, as mentioned previously, I am simply searching for the word nmap. However I did a little research online and there seems to be other possible ways of detecting nmap scans with more reliability (though each way has its pros and cons). I would be interested in exploring and implementing some of these to create a more robust nmap scan
