#!/usr/bin/python
# Multi-threaded X-Forwarded-For header comparer
# v.0.1

from threading import Thread
import time,requests,sys,threading,Queue,random
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class XFFSniffer(Thread):
    def __init__(self,work_queue,output_lock):
        Thread.__init__(self)
        self.work_queue = work_queue
        self.output_lock = output_lock

    def run(self):
        while True:
            try:
                domain = self.work_queue.get()
                print "[+] Checking:", domain
                alpha = self.handleResource(domain)
                beta = self.handleResource(domain,XFF=True)
                diff = alpha-beta
                output = domain,alpha,beta,diff
                self.write_to_file(output)
            finally:
                self.work_queue.task_done()

    def handleResource(self,URI,XFF=False):
        # p = {'http':'http://127.0.0.1:8080','https':'https://127.0.0.1:8080'}
        headers = {'User-Agent':'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0'}
        if XFF:
            headers.update({'X-Forwarded-For':'127.0.0.1','X-Forwarded-IP':'127.0.0.1'})
        try:
            response = requests.get(URI,verify=False,timeout=8,headers=headers)
            return int(len(response.content))
        except Exception as e:
            print "[!] Something went wrong", e
            #print error in log file?
            return 0

    def write_to_file(self,string):
        while self.output_lock.locked():
            continue
        self.output_lock.acquire()
        with open("xff_results.txt", "a+") as file:
            file.write(str(string)+"\n")
            file.close()
        self.output_lock.release()

def check_args():
    if(len(sys.argv) != 3):
        print "Usage: xffcomp.py <domains_file> <thread_count>\ne.g. xffcomp.py ./targets.txt 10";
        sys.exit(1)

if __name__ == '__main__':
    check_args()
    output_lock = threading.Lock()
    queue = Queue.Queue()
    for x in range(int(sys.argv[2])):
        sniff = XFFSniffer(queue,output_lock)
        sniff.daemon = True
        sniff.start()
    #populate and start the queue
    f = open(sys.argv[1])
    for domain in f:
        queue.put(domain.strip())
    f.close()
    queue.join()
