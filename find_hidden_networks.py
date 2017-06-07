#!/usr/bin/python
"""
RedSpectrum - find_hidden_networks.py
April 1, 2017
Leopold von Niebelschuetz-Godlewski

Finds hidden networks.
"""
import argparse, os, sys, time
from core import check_SSIDs, clean_AP_data, clean_station_data, clean_user_input, deauth, disable_interfering_processes, disable_monitor_mode, enable_monitor_mode, find_output_files, kill_process, print_error, print_success, print_warning, run_process
from core import MAX_CLIENT_DEAUTH, MIN_ACKs
from parse_airodump import parse_APs, parse_stations, split_CSVs

def findHiddenNetworks(target_bssid,target_ssids,ListenInterface,AttackInterface,verbose=True):
	discovered = []
	tested     = []
	cleanAPs   = clean_AP_data(APs)
	for bssid,essid,channel,privacy,authentication,AP_date in cleanAPs:
		if target_bssid and (not target_bssid.lower() in bssid.lower()): continue
		if '\\x00' in essid or not essid:
			cleanStations = clean_station_data(stations)
			for station_mac,connected_bssid,station_date in cleanStations:
				if (bssid == connected_bssid and channel != '-1') and (not (bssid,station_mac) in tested) and (not bssid in [d[0] for d in discovered]):
					invalidTargetUnmasked					= False
					numOfDiscovered                         = len(discovered)
					outFileName                             = "HIDDEN_%s_%s" % (bssid,channel)
					(ACK,(ListenInterface,AttackInterface)) = deauth(bssid,channel,station_mac,MAX_CLIENT_DEAUTH,outFileName,ListenInterface,AttackInterface,verbose)
					outFileNames,outCSVFile 				= find_output_files(outFileName,'.csv')
					APFileName             				    = 'APs_'+outFileName+'.csv'
					stationFileName         				= 'stations_'+outFileName+'.csv'
					split_CSVs(inputFiles=[outCSVFile],APFileName=APFileName,stationFileName=stationFileName)
					discoveredAPs      = parse_APs(APFileName)
					cleanDiscoveredAPs = clean_AP_data(discoveredAPs)
					for dis_bssid,dis_essid,dis_channel,dis_privacy,dis_authentication,dis_AP_date in cleanDiscoveredAPs:
						if (dis_essid and not '\\x00' in dis_essid) and (not target_ssids or dis_essid.lower() in target_ssids):
							newOutCSVFile = outCSVFile.replace("HIDDEN_", "W00T-UNHIDDEN_%s_" % '+'.join(dis_essid.split()))
							os.rename(outCSVFile, newOutCSVFile)
							if verbose: print_success("\"%s\" discovered! Output written to \"%s\"" % (dis_essid,newOutCSVFile))
							discovered.append((bssid,dis_essid))
						if (dis_essid and not '\\x00' in dis_essid) and (target_ssids and not dis_essid.lower() in target_ssids):
							invalidTargetUnmasked = True
							print_warning("\"%s\" was discovered, but output was not stored..." % dis_essid)
					if (ACK >= MIN_ACKs) and (len(discovered) == numOfDiscovered) and not invalidTargetUnmasked:
						if verbose: print_warning("Too many deauthentication packets sent to \"%s\", the station's wireless card is having issues reconnecting... Try running this script against \"%s\" later..." % (station_mac,bssid))
					for outputFile in outFileNames:
						try:
							os.remove(outputFile)
						except:
							pass
					os.remove(APFileName)
					os.remove(stationFileName)
					tested.append((bssid,station_mac))
				else:
					pass
	if not tested:
		if verbose: print_error("No clients are connected to target SSID(s) and/or BSSID...")
	return discovered

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
	stations   				   = parse_stations()
	disable_interfering_processes()
	discovered 				   = findHiddenNetworks(args.bssid,ssids,clean_user_input(args.ListenInt),clean_user_input(args.AttackInt))
	for file in (APFileName,stationFileName):
		try:
			os.remove(file)
		except:
			pass