When you’re in an environment where you see tens/hundreds of access points and clients it can be tedious to accurately leverage Airodump-ng output data (both for reporting purposes and formulating attacks). This tool ingests Airodump-ng CSV files to uncover hidden networks, capture PSKs, deauthenticate clients, quickly identify key information for target SSID(s) and format all recon data for reporting purposes.
<BR><BR>
<B>Features:</B>
<BR><BR>
- Print formatted table including access points and client recon data. Output can be limited to specific SSID(s).

<pre>
  usage: parse_airodump.py [-h] [-c CSV [CSV ...]] [-s SSIDS [SSIDS ...]]
                           company
                           
  positional arguments:
    company               target company name (e.g. "Trustave SpiderLabs")
    
  optional arguments:
    -h, --help            show this help message and exit
    -c CSV [CSV ...], --csv CSV [CSV ...]
                          Airodump-ng output files (e.g. inside.csv outside.csv)
    -s SSIDS [SSIDS ...], --ssids SSIDS [SSIDS ...]
                          target SSIDs (e.g. "Secured WiFi" CorpNet LabNet)
</pre>

- Deauthentication attack. Target(s) can be limited to specific stations, BSSID(s) or SSID(s).

<pre>
  usage: deauth_attack.py [-h] [-b BSSID] [-c CSV [CSV ...]]
                          [-s SSIDS [SSIDS ...]] [-t STATION]
                          ListenInt AttackInt
                          
  positional arguments:
    ListenInt             wireless interface name to be used for listening (e.g.
                          wlan0)
    AttackInt             wireless interface name to be used for attacking (e.g.
                          wlan0)
                          
  optional arguments:
    -h, --help            show this help message and exit
    -b BSSID, --bssid BSSID
                          target BSSID (e.g. 6a:55:35:9b:9b:69)
    -c CSV [CSV ...], --csv CSV [CSV ...]
                          Airodump-ng output files (e.g. inside.csv outside.csv)
    -s SSIDS [SSIDS ...], --ssids SSIDS [SSIDS ...]
                          target SSIDs (e.g. "Secured WiFi" CorpNet LabNet)
    -t STATION, --station STATION
                          target client station (e.g. ca:82:62:2e:4a:99)
</pre>

- Find hidden networks. Target(s) can be limited to specific BSSID(s) or SSID(s).

<pre>
  usage: find_hidden_networks.py [-h] [-b BSSID] [-c CSV [CSV ...]]
                                 [-s SSIDS [SSIDS ...]]
                                 ListenInt AttackInt
                                 
  positional arguments:
    ListenInt             wireless interface name to be used for listening (e.g.
                          wlan0)
    AttackInt             wireless interface name to be used for attacking (e.g.
                          wlan0)
                          
  optional arguments:
    -h, --help            show this help message and exit
    -b BSSID, --bssid BSSID
                          target BSSID (e.g. 6a:55:35:9b:9b:69)
    -c CSV [CSV ...], --csv CSV [CSV ...]
                          Airodump-ng output files (e.g. inside.csv outside.csv)
    -s SSIDS [SSIDS ...], --ssids SSIDS [SSIDS ...]
                          target SSIDs (e.g. "Secured WiFi" CorpNet LabNet)
</pre>

- Get WPA handshakes. Target(s) can be limited to specific BSSID(s) or SSID(s).

<pre>
  usage: get_handshakes.py [-h] [-b BSSID] [-c CSV [CSV ...]]
                           [-s SSIDS [SSIDS ...]]
                           ListenInt AttackInt

  positional arguments:
    ListenInt             wireless interface name to be used for listening (e.g.
                          wlan0)
    AttackInt             wireless interface name to be used for attacking (e.g.
                          wlan0)

  optional arguments:
    -h, --help            show this help message and exit
    -b BSSID, --bssid BSSID
                          target BSSID (e.g. 6a:55:35:9b:9b:69)
    -c CSV [CSV ...], --csv CSV [CSV ...]
                          Airodump-ng output files (e.g. inside.csv outside.csv)
    -s SSIDS [SSIDS ...], --ssids SSIDS [SSIDS ...]
                          target SSIDs (e.g. "Secured WiFi" CorpNet LabNet)
</pre>
