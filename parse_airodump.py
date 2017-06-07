#!/usr/bin/python
"""
RedSpectrum - parse_airodump.py
April 1, 2017
Leopold von Niebelschuetz-Godlewski

Looks in the CWD for Airodump-ng .csv output files, and prints two tables containing wireless reconnaissance details.
"""
import argparse, csv, os, sys
from core import print_error, print_warning, print_success
try:
	from prettytable import PrettyTable
except:
	print_error("You must install PrettyTable module first... Exiting...")
	sys.exit(1)

AP_FILE_NAME        = "APs.csv"
STATION_FILE_NAME   = "stations.csv"

def parse_APs(fileName=AP_FILE_NAME):
	APs = []
	with open(fileName) as csvFile:
		reader = csv.DictReader(csvFile)
		for row in reader:
			if row['BSSID'] != "00:00:00:00:00:00":
				APs.append((row['BSSID'].strip(), row[' ESSID'].strip(), row[' channel'].strip(),row[' Privacy'].strip(),row[' Authentication'].strip(),row[' Last time seen'].strip().split()[0]))
	return APs

def parse_stations(fileName=STATION_FILE_NAME):
	stations = []
	with open(fileName) as csvFile:
		reader = csv.DictReader(csvFile)
		for row in reader:
			if "not associated" in row[' BSSID']: continue
			stations.append((row['Station MAC'].strip(), row[' BSSID'].strip(), row[' Last time seen'].strip().split()[0]))
	return stations

def split_CSVs(inputFiles=[],APFileName=AP_FILE_NAME,stationFileName=STATION_FILE_NAME):
	APs = []
	stations = []
	try:
		if not inputFiles:
			csvFiles = [file for file in os.listdir('.') if file.endswith('.csv') and not 'kismet' in file and file != AP_FILE_NAME and file != STATION_FILE_NAME]
		else:
			csvFiles = inputFiles
		if not csvFiles:
			raise Exception("No CSV files found in the CWD...")
		for csvFile in csvFiles:
			csvFileObject = open(csvFile)
			csvContent    = csvFileObject.read()
			csvContent    = csvContent.split('\r\n\r\n')
			for line in csvContent[0].split('\n'):
				if len(line)>1 and not "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication" in line:
					APs.append(line)
			for line in csvContent[1].split('\n'):
				if len(line)>1 and not "Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs" in line:
					stations.append(line)
			csvFileObject.close()
		APs      = "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\n" + '\n'.join(APs)
		stations = "Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs\n" + '\n'.join(stations)
		open(APFileName,'w').write(APs)
		open(stationFileName,'w').write(stations)
	except:
		print_error("You must run this from a directory containing Airodump-ng CSV output files and ensure you don't have any other CSV files in the CWD... Exiting...")
		sys.exit(1)
	return APFileName,stationFileName

if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("company", help="target company name (e.g. \"Trustave SpiderLabs\")", type=str)
	parser.add_argument("-c", "--csv", help="Airodump-ng output files (e.g. inside.csv outside.csv)", type=str, nargs='+')
	parser.add_argument("-s", "--ssids", help="target SSIDs (e.g. \"Secured WiFi\" CorpNet LabNet)", type=str, nargs='+')
	args = parser.parse_args()

	if args.ssids:
		ssids = [ssid.lower() for ssid in args.ssids]
		print_warning("Searching for access points broadcasting and clients connected to the following SSIDs:")
		for SSID in ssids:
			print '\t'+SSID
		print ''
	else:
		ssids = args.ssids

	split_CSVs(args.csv)
	APs         = parse_APs()
	stations    = parse_stations()

	APHeader      = ["DATE", "ESSID", "BSSID", "CHANNEL", "PRIVACY", "AUTHENTICATION"]
	APTable       = PrettyTable(APHeader)
	allAPs        = []
	stationHeader = ["DATE", "ESSID", "BSSID", "CHANNEL", "CONNECTED CLIENT MAC ADDRESS"]
	stationTable  = PrettyTable(stationHeader)
	allStations   = []

	for bssid,essid,channel,privacy,authentication,AP_date in APs:
		if channel == "-1": continue
		if '\\x00' in essid or not essid:
			essid = "<HIDDEN NETWORK>"
		if (ssids and essid.lower() in ssids and (AP_date,bssid,essid) not in allAPs) or (not ssids and (AP_date,bssid,essid) not in allAPs):
			allAPs.append((AP_date,bssid,essid))
			APTable.add_row([AP_date,essid,bssid,channel,privacy,authentication])
			for station_mac,connected_bssid,station_date in stations:
				if bssid == connected_bssid and not (station_date,station_mac,connected_bssid,essid) in allStations:
					allStations.append((station_date,station_mac,connected_bssid,essid))
					stationTable.add_row([station_date,essid,bssid,channel,station_mac])
				else:
					pass

	print "%s SSID(s) (non-exhaustive list):" % args.company
	print APTable
	print "%s client(s) (non-exhaustive list):" % args.company
	print stationTable