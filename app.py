import os
import flask
from flask import Flask, request, Response, g
from functools import partial


app = Flask(__name__) 
app.config["DEBUG"] = True 

nar = {
"bit1":
"<size=50><b> Beginning of the Attack </b></size=50> \n\n A phishing email is sent to the receptionist of the Hospital asking them to log in to the HR system and confirm urgently the number of annual leave days they have left. \n\n Zoom in to the Hospital building to the HR office to observe how the cyber attack will play out.", 

"bit2":
"<size=50><b> Phishing Successful </b></size=50> \n\n The employee clicks on the link in the fake email and is redirected to a fake web page. It looks identical to the hospital's HR management system. \n\nThey login to the web page with their credentials.",
    
"bit3":
"<size=50><b> Credentials are stolen </b></size=50> \n\n The user is now redirected to the real HR system login page and to them, it seems like they have entered their password incorrectly.",

"bit4":
"<size=50><b> Warning </b></size=50> \n\n The attacker connects to the hospital's VPN! \n\n Having stolen the employee's credentials, the attacker has now successfully logged in to the hospital's VPN network!",

"bit5":
" <size=50><b> Malware Launched </b></size=50> \n\n Having gained access to the network, the attacker is now launching a worm (i.e. worm.win32.kino.kf). \n\n The worm is able to find vulnerable nearby machines and can compromise them by brute-forcing their credentials.",

"bit6":
"<size=50><b> PACS server is compromised </b></size=50> \n\n A backdoor on the server allows the attacker to extract sensitive patient data and usernames/passwords of hospital employees who have previously logged onto the server.",

"bit7":
"<size=50><b> Warning </b></size=50> \n\n Some suspicious activity on the network has been detected.",

"bit8":
"<size=50><b>Measure ineffective</b></size=50> \n\n In the meantime, the attacker scans the internal hospital network and identifies an open VPN server connecting another network.",

"bit9":
"<size=50><b>University VPN credentials Stolen </b></size=50> \n\n The attacker successfully steals VPN credentials from PACS server and logs onto the VPN.",

"bit10":
"<size=50><b>Attacker performs Recon</b></size=50> \n\n Having accessed the network, the attacker scans the network and identifies an IP range. \n\n Following an IP lookup, they identify that the server is part of a University medical research lab.",

"bit11":
" <size=50><b> Warning </b></size=50> \n\n The attacker has now access to the University's network",

"bit12":
"<size=50><b>Attacker identifies credential server</b></size=50> \n\n The adversary is now able to extract hashed credentials for local IT systems on which experimental virus vaccination experiment details are stored.",

"bit13":
"<size=50><b>Warning </b></size=50> \n\n Suspicious scanning activity is detected on the network!"
}


import platform, os
import functools
import time

from datetime import datetime


# util functions
def logger(logfolder='logs'):
    """Defines folder and file name for logging and returns logger func.
    
    If specified folder does not exist, it creates it. In addition, it closes
    over logfile variable giving read-only access to nested log_line func.
    Returns a log_line function that will consistently write log strings
    to the logfile in the specified logfolder.
    
      Typical usage example:
      
      log_line = logger("logfolder")
      log_line("log this line")
    """
    
    def log_line(txt, console=False, console_first=False, at="info"):
        if at != "":
            at = " at={}".format(at)
        line = lambda: "{}:{} {}".format(datetime.now(), at, txt)
        
        if console and console_first:
            print(line())
    
        with open(logfile, 'a') as lf:
            print(line() + "\n", file=lf)
        
        if console and not console_first:
            print(line())
    
    os.makedirs(logfolder, exist_ok=True)
    tstamp = datetime.now().strftime("%d.%m.%YT%H%M%S.%f%z")
    logfile = logfolder + "/log_{}.txt".format(tstamp)
    
    return log_line

def headers_length(headers):
    COLON_LEN = 1
    WHITESPACE_LEN = 1
    CRLF_LEN = 2
    return sum(len(key) + COLON_LEN + WHITESPACE_LEN + len(value) + CRLF_LEN for key, value in headers.items()) + CRLF_LEN

def request_length(request):
    # get length of first line: "{method} {path} HTTP/1.1{CRLF}"
    first_line = len(request.method) + len(request.path) + 12  # magic 12 is len of request protocol
    headers_len = headers_length(request.headers)
    content_len = int(request.headers.get("content-length", 0))
    
    # add all together
    return first_line + headers_len + content_len

def response_length(response):
    # get length of first line: "HTTP/1.0 {status}{CRLF}"
    first_line = len(response.status) + 11  # magic 11 is len of protocol and whitespaces
    headers_len = headers_length(response.headers)
    content_len = int(response.headers.get("content-length", 0))
    
    # add all together
    return first_line + headers_len + content_len

sysinfo = """System Information
System: {sys.system} {sys.version}, {sys.processor}
Node: {sys.node}

Logs:""".format(sys = platform.uname())

log = logger()
log(sysinfo, at="")
log_console = partial(log, console=True, console_first=True)


@app.before_request
def before_request():
    """This is called before the request is handled by the route(view) function.
    
    Store request receipt timestamp in request context variable: g.
    """
    
    g.request_tstamp, g.request_time = datetime.now(), time.process_time()
    

@app.after_request
def after_request(response):
    """ """
    
    # request details
    ga = dict()
    ga["method"] = request.method
    ga["path"] = request.path
    ga["status"] = response.status_code
    
    # remote user
    ga["ip"] = request.remote_addr
    ga["host"] = request.host
    ga["protocol"] = request.scheme
    ga["client"] = "{} v{}".format(request.user_agent.browser, request.user_agent.version)
    ga["platform"] = request.user_agent.platform
    
    # packet size
    ga["request_bytes"] = request_length(request)
    ga["response_bytes"] = response_length(response)
    
    # timing
    ga["request_tstamp"] = g.request_tstamp
    ga["request_time"] = g.request_time
    
    if "bit" in request.path:
    
        @response.call_on_close
        def after_response():
            SEC_TO_MILLISECONDS = 1000
            nonlocal ga
            ga["response_tstamp"], ga["response_time"] = datetime.now(), time.process_time()
            service = ga["response_tstamp"] - ga["request_tstamp"]
            ga["service"] = "{:.3f}ms".format(service.total_seconds() * SEC_TO_MILLISECONDS)
            
            message = ' '.join(list("=".join((key,str(value))) for key, value in ga.items()))
            log_console(message)
    
    return response
    

@app.teardown_request
def teardown_request(e):
    """This is called at the very end of each request regardless of prior exceptions.
    
    This function must not fail - use try/except blocks to handle exceptions.
    """
    
    if "bit" in request.path:
        log_console('Request to path={} finished. Context torn down.'.format(request.path))


@app.route('/<bit>', methods=['GET'])
def home(bit):
    
    if bit in nar:
        retval = nar[bit]
        
    else:
        retval = f"Key {bit} does not exist. Check for errors in the path."
    
        if "bit" in bit:
            log("Error occurred. Key {} requested but not found".format(bit), at="error")
    
    return retval
    

if (__name__ == "__main__"):
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))