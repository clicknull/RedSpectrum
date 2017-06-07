#!/usr/bin/python
"""
RedSpectrum
April 1, 2017
Leopold von Niebelschuetz-Godlewski

Configuration options.
"""
FLUSH_WRITE_TIME  = 5  #Don't mess with unless you're getting CSV read errors, if so, increase this value.
MAX_CLIENT_DEAUTH = 10 #This is the amount of deauthentication packets sent to clients. Edit as necessary.
MAX_DEAUTH_TRIES  = 3  #Maximum deauthentication attempts. Edit as necessary.
MAX_PROC_WAIT     = 60 #Maximum seconds to wait for (some) processes to complete.
MIN_ACKs          = 20 #Minimum ACKs required to avoid retrying the deauthentication attack.
PROC_DATA_TIME    = 5  #Don't mess with this unless you're not getting handshakes although enough ACKs, if this happens often, increase this value.
WALK_TIME         = 15 #Seconds to walk around after insufficient ACKs, target BSSID broadcasts, etc. Edit as necessary.
