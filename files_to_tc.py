#!/usr/bin/env python
# Copyright (C) ThreatConnect, Inc - All Rights Reserved
# Unauthorized copying of this file, via any medium is strictly prohibited
# Proprietary and confidential
# Written by Wes Hurd <whurd@threatconnect.com>, June 2015

import argparse
import ConfigParser
import hashlib
import os
from threatconnect import ThreatConnect
from threatconnect.Config.ResourceType import ResourceType

# API Config
config_file = "tc.conf"
config = ConfigParser.RawConfigParser()
config.read(config_file)
try:
    api_access_id = config.get('threatconnect', 'api_access_id')
    api_secret_key = config.get('threatconnect', 'api_secret_key')
    api_default_org = config.get('threatconnect', 'api_default_org')
    api_base_url = config.get('threatconnect', 'api_base_url')
except ConfigParser.NoOptionError:
    print('Could not read configuration file.')
tc = ThreatConnect(api_access_id, api_secret_key, api_default_org, api_base_url)

# This function obtains hashes and size of a local file.
def getFileInfo(inFile):
    # Read file content into str object.
    content = open(inFile, "rb").read()
    
    # Calculate hashes from content string.
    # Calculating hashes directly from the file open object using hashlib.md5(inFile).hexdigest will give incorrect hashes because it only takes 128 bytes.
    md5 = hashlib.md5(content).hexdigest()
    sha1 = hashlib.sha1(content).hexdigest()
    sha256 = hashlib.sha256(content).hexdigest()
    size = os.path.getsize(inFile)
    fileName = os.path.basename(inFile)
    return md5, sha1, sha256, size, fileName

# Function to add a single file indicator to TC.
def fileToTC(md5, sha1, sha256, size, rating, confidence):
    indicators = tc.indicators()
    fileIndicator = indicators.add(md5)
    fileIndicator.set_indicator(sha1, ResourceType.FILES)
    fileIndicator.set_indicator(sha256, ResourceType.FILES)
    fileIndicator.set_rating(rating)
    fileIndicator.set_confidence(confidence)
    fileIndicator.set_size(size)
    fileIndicator.commit()
    return fileIndicator

def filesToTC(files, rating, confidence):
    indicators = tc.indicators()
    
    # Ask user if they know file is in VT. This will come into play later for auto-sourcing with VT link.
    isInVT = raw_input("Is the file(s) in VirusTotal? [y/n] (If unknown, type n): ")
    if isInVT.lower() == 'n':
        source = raw_input("Enter the default source attribute to be used for the file(s): ").strip()
    
    # Ask user to enter a description attribute for the files.
    desc = raw_input("Enter the default description attribute to be used for the file(s): ").strip()
    
    # Ask user if they want to associate the files to an existing known incident.
    associateToInc = raw_input("Would you like to associate the file(s) to an existing incident? [y/n] ")
    if associateToInc.lower() == 'y':
        incURL = raw_input("Enter the URL or ID of the incident to associate: ")
        incId = incURL.strip("https://app.threatconnect.com/auth/incident/incident.xhtml?incident=")
        incidents = tc.incidents()
    elif associateToInc.lower() == 'n':
        pass
    
    # Ask user if they want to associate the files to an existing known threat.
    associateToThreat = raw_input("Would you like to associate the file(s) to an existing threat? [y/n] ")
    if associateToThreat.lower() == 'y':
        threatURL = raw_input("Enter the URL or ID of the threat to associate: ")
        threatId = threatURL.strip("https://app.threatconnect.com/auth/threat/threat.xhtml?threat=")
    elif associateToThreat.lower() == 'n':
        pass
    
    # Iterate through the given files, obtain their information, and add them as indicators into TC.
    for fileInstance in files:
        # Call getFileInfo and fileToTC functions.
        md5, sha1, sha256, size, fileName = getFileInfo(fileInstance)
        fileIndicator = fileToTC(md5, sha1, sha256, size, rating, confidence) # fileToTC returns fileIndicator object, needed for adding attributes and associations.
        
        # If the user specified that the file(s) was in VT, create a standard VT source URL.
        if isInVT.lower() == 'y':
            # This is the standard VT URL source path.
            source = "https://www.virustotal.com/file/" + sha256 + "/analysis/"
        
        # Add the attributes to the file object.
        fileIndicator.add_attribute("Description", desc)
        fileIndicator.add_attribute("Source", source)
        
        # Add the filename to the TC file object.
        fileIndicator.add_file_occurrence(fileName)
        
        # Associate the files to the given incident if specified.
        if associateToInc.lower() == 'y':
            fileIndicator.associate_group(ResourceType.INCIDENTS, incId)
        
        # Associate the files to the given threat if specified.
        if associateToThreat.lower() == 'y':
            fileIndicator.associate_group(ResourceType.THREATS, threatId)
        
        # Commit attributes and associations.
        fileIndicator.commit()

def main():
    # Command-line syntax and help section here.
    parser = argparse.ArgumentParser(
        description="Reads local file(s) and adds their hashes, filesize into TC, with the options to create attributes and associate to groups.")
    parser.add_argument("-f", "--files", dest="files", required=True, help="File name of target file(s).", type=str,
                        nargs="+")
    parser.add_argument("-r", "--rating", dest="rating", help="Evilness rating from 0-5 of target file(s).", type=float,
                        nargs=1)
    parser.add_argument("-c", "--confidence", dest="confidence", help="confidence rating from 0-100 of target file(s).",
                        type=int, nargs=1)
    parser.add_argument('-V', '--version', action='version', version="1.5.2")
    args = parser.parse_args()
    for arg in args.files:
        if not os.path.exists(arg):
            parser.error("The file %s does not exist!" % arg)
    if args.rating is None:
        rating = float(input("Enter the evilness rating from 0-5 of target file(s): "))
    else:
        rating = args.rating[0]
    if args.confidence is None:
        confidence = input("Enter the confidence from 0-100 of target file(s): ")
    else:
        confidence = args.confidence[0]

    filesToTC(args.files, rating, confidence)

main()
