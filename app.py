import os
import flask


app = flask.Flask(__name__) 
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


@app.route('/<bit>', methods=['GET']) 
def home(bit):
    if bit in nar:
        return nar[bit]
        
    else:
        return f"Key {bit} does not exist."

if (__name__ == "__main__"):
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))