#!/bin/python3

import os
import pyclamd
import yara
import shutil
import re
import sys
import PyPDF2


## 3 functions in one big scan function called scan directory, uses mupdf to perform object ecxtraction
#sys module imported to be able to start PyPDF2
#re module for regex pattern matching
#os module for directory readingga actions
#shutil for move operation-s a module in Python's standard library that provides a high-level interface for file operations. It offers functions for various file-related tasks, 

all_file_messages = {
    "clamav_scan": "",
    "yara_check": "",
    "move_to_quarantine": ""
}
all_messages = []
# Connect to ClamAV daemon
try:
    cd = pyclamd.ClamdUnixSocket()
except pyclamd.ConnectionError as e:
    print(f"ClamAV connection error: {e}")
    exit(1)

# Load YARA rules
#yara_rules = yara.compile('./cyb_tst.yar')
#yara_rules = yara.compile('./obs.yar')
yara_rules = yara.compile('./ablh.yar')


# Define the path of the directory to be scanned
directory_path = os.path.expanduser('./uploads')

# Move file to quarantine directory
def move_to_quarantine(file_path):
    home_dir = os.path.expanduser("~")
    quarantine_dir = os.path.join(home_dir, "quarantine")

    # Create the quarantine directory if it doesn't exist
    if not os.path.exists(quarantine_dir):
        os.makedirs(quarantine_dir)

    # Get the filename from the file path
    file_name = os.path.basename(file_path)

    # Construct the destination path in the quarantine directory
    dest_path = os.path.join(quarantine_dir, file_name)

    # Move the file to the quarantine directory
    shutil.move(file_path, dest_path)
    all_file_messages['move_to_quarantine'] = f"quarantine"
    all_file_messages['clamav_scan'] = ""
    all_file_messages['yara_check'] = ""
    all_messages.append(f"File {file_path} moved to quarantine directory: {dest_path}")
    print(f"File {file_path} moved to quarantine directory: {dest_path}")

# Perform ClamAV scan
def clamav_scan(file_path):
    print('clamav_scan')
    with open(file_path, 'rb') as f:
        file_contents = f.read()

    result = cd.scan_stream(file_contents)

    if result is None:
        all_file_messages['clamav_scan'] = f'{file_path} no ClamAV signature detected'
        all_messages.append(f'{file_path} no ClamAV signature detected')
        print(f'{file_path} ino ClamAV signature detected')
    elif file_path in result:
        if result[file_path][0] == 'OK':
            all_file_messages['clamav'] = f"{file_path} no ClamAV signature detected"
            all_messages.append(f'{file_path} no ClamAV signature detected')
            print(f'{file_path} no ClamAV signature detected')
    else:
        all_file_messages['clamav'] = f"Scan result: {result} in {file_path}"
        all_messages.append(f'Scan result: {result} in {file_path}')
        print(f'Scan result: {result} in {file_path}')
        move_to_quarantine(file_path)

# Check file against YARA rules
def yara_check(file_path):
    # Check if the file exists
    if not os.path.exists(file_path):
        return

    matches = yara_rules.match(file_path)
    if matches:
        all_file_messages['yara_check'] = f"{file_path} matches YARA rule: {matches}"
        all_messages.append(f'{file_path} matches YARA rule: {matches}')
        print(f'{file_path} matches YARA rule: {matches}')
        move_to_quarantine(file_path)
    else:
        all_file_messages['yara_check'] = f"{file_path} does not match any YARA rule"
        all_messages.append(f'{file_path} does not match any YARA rule')
        print(f'{file_path} does not match any YARA rule')


# Check extracted objects against YARA rules
def yara_check_extracted_objects(file_path, extracted_objects):
    # Check if the file exists
    if not os.path.exists(file_path):
        return

    if extracted_objects:
        matches = yara_rules.match(data=extracted_objects)
        if matches:
            all_messages.append(f'Extracted objects from {file_path} match YARA rule: {matches}')
            print(f'Extracted objects from {file_path} match YARA rule: {matches}')
            move_to_quarantine(file_path)
        else:
            all_messages.append(f'{file_path} No YARA rule found in PDF Objects')
            print(f'{file_path} No YARA rule found in PDF Objects')
    else:
        all_messages.append(f'{file_path} No extracted objects found in PDF')
        print(f'{file_path} No extracted objects found in PDF')



def pdf_analysis(file_path):
    try:
        # Check if the file exists
        if not os.path.exists(file_path):
            # all_messages.append()
            print(f'File {file_path} does not exist. Skipping PDF analysis.')
            return

        # Open the PDF file
        with open(file_path, 'rb') as file:
            # Create a PDF reader object
            reader = PyPDF2.PdfReader(file)

            # Extract JavaScript objects
            js_objects = []
            for page in reader.pages:
                if '/JavaScript' in page:
                    js_objects.append(page['/JavaScript'])

            # Extract OpenAction objects
            openaction_objects = []
            if '/OpenAction' in reader.trailer:
                openaction_objects.append(reader.trailer['/OpenAction'])

                 # Extract OpenAction objects
            action_objects = []
            if '/Action' in reader.trailer:
                action_objects.append(reader.trailer['/Action'])

            # Extract URI Action objects
            uri_action_objects = []
            for page in reader.pages:
                if '/Annots' in page:
                    annotations = page['/Annots']
                    for annotation in annotations:
                        if '/A' in annotation:
                            action = annotation['/A']
                            if action.get('/S') == '/URI':
                                uri = action.get('/URI')
                                if uri:
                                    uri_action_objects.append(uri)

            # Extract EmbeddedFiles objects
            embedded_files = []
            if '/EmbeddedFile' in reader.trailer:
                embedded_files = reader.trailer['/EmbeddedFile']

            if embedded_files:
                # Move the PDF file to quarantine
                move_to_quarantine(file_path)

            # Combine the extracted objects
            extracted_objects = js_objects + openaction_objects + action_objects + uri_action_objects 

            # Perform YARA check with extracted objects
            yara_check_extracted_objects(file_path, extracted_objects)

    except Exception as e:
        print(f'Error analyzing PDF: {e}')


# Recursively scan the directory contents
def scan_directory(directory_path):
    for root, dirs, files in os.walk(directory_path):
        for file_name in files:
            # Get the absolute path of the file
            file_path = os.path.join(root, file_name)

             # Perform ClamAV scan
            clamav_scan(file_path)


            # Perform YARA check
            yara_check(file_path)

            # Perform PDF analysis
            pdf_analysis(file_path)

           

# Start scanning the directory
# scan_directory(directory_path)
