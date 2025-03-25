#!/usr/bin/env python3

"""
This script retrieves a list of drives used by ZFS, fetches details about those disks, and
then turns on the SAS fail/locator light for each drive this is in an abnormal state.

Author: Tyler Kerr
Date: 03/2025
"""

import subprocess
import re
import os
import concurrent.futures
import hashlib
import json
import time
from datetime import datetime

CACHE_FILE = "/tmp/zfs_sas_device_cache.json"
CACHE_MAX_AGE = 3600
SAFE_DRIVE_STATUSES = ("ONLINE", "AVAIL")

def get_drive_state_hash(drives):
    """Generate a hash representing the current state of all drives"""
    drive_data = []
    for drive in sorted(drives, key=lambda d: d['name']):
        drive_data.append(f"{drive['name']}:{drive['status']}:{drive['wwn']}:{drive.get('locate', '')}")
    
    state_string = "|".join(drive_data)
    return hashlib.md5(state_string.encode('utf-8')).hexdigest()

def load_cache():
    """Load cached SAS device information if available and valid"""
    try:
        if not os.path.exists(CACHE_FILE):
            print("Cache file does not exist")
            return None
        
        with open(CACHE_FILE, 'r') as f:
            cache = json.load(f)
        
        if time.time() - cache.get('timestamp', 0) > CACHE_MAX_AGE:
            print("Cache has expired")
            return None
            
        return cache
    except Exception as e:
        print(f"Error loading cache: {e}")
        return None

def save_cache(drives, sas_devices):
    """Save drive and SAS device information to cache with hash"""
    try:
        # Generate a hash of the current drive state
        state_hash = get_drive_state_hash(drives)
        
        cache = {
            'timestamp': time.time(),
            'date': datetime.now().isoformat(),
            'state_hash': state_hash,
            'drives': [{'name': d['name'], 'status': d['status'].upper(), 'wwn': d['wwn'], 'locate': d.get('locate', '')} for d in drives],
            'sas_devices': sas_devices
        }
        
        with open(CACHE_FILE, 'w') as f:
            json.dump(cache, f)
    except Exception as e:
        print(f"Error saving cache: {e}")

def is_cache_valid(cache, drives):
    """Check if cache is valid using hash comparison"""
    if not cache or 'state_hash' not in cache:
        return False
    
    current_hash = get_drive_state_hash(drives)
    if current_hash != cache['state_hash']:
        print("Drive state has changed, invalidating cache")
        return False
    else:
        return True

def get_zpool_drives():
    """Query zpool to get a list of drives and their statuses"""
    output = subprocess.check_output(['zpool', 'status', '-LP'], text=True)

    regex = re.compile(
        r'^\s+(?P<drive>(?:/dev/)?sd[a-z]\d*)\s+(?P<status>\S+)',
        re.MULTILINE
    )

    drives = []
    for match in regex.finditer(output):
        drive_name = match.group('drive')
        if drive_name.startswith("/dev/"):
            drive_name = drive_name[len("/dev/"):]
        status = match.group('status')
        drives.append({
            "name": drive_name,
            "status": status,
            "serial": "",
            "wwn": "",
            "enclosure": "",
            "slot": "",
            "sas_version": "",
            "locate": ""
        })
    return drives

def get_drive_identifiers(drive):
    """Retrieve both the short serial and WWN for a drive"""
    device_path = os.path.join("/dev", drive["name"])
    identifiers = {"serial": "", "wwn": ""}
    try:
        result = subprocess.run(
            ["udevadm", "info", "--query=all", "--name=" + device_path],
            capture_output=True, text=True
        )
        for line in result.stdout.splitlines():
            if "ID_SERIAL_SHORT=" in line and not identifiers["serial"]:
                identifiers["serial"] = line.split("ID_SERIAL_SHORT=", 1)[1].strip()
            if "ID_WWN=" in line and not identifiers["wwn"]:
                wwn = line.split("ID_WWN=", 1)[1].strip()
                if wwn.lower().startswith("0x"):
                    wwn = wwn[2:]
                identifiers["wwn"] = wwn
    except Exception as e:
        print(f"Error retrieving identifiers for {device_path}: {e}")
    return identifiers

def populate_drive_identifiers(drives):
    """Retrieve identifiers for each drive and populate the drive objects"""
    with concurrent.futures.ThreadPoolExecutor() as executor:
        results = list(executor.map(get_drive_identifiers, drives))
    
    for i, ids in enumerate(results):
        drives[i]["serial"] = ids["serial"]
        drives[i]["wwn"] = ids["wwn"]

def get_sas_devices(sas_version):
    """Run a sas#ircu command and parse the output"""

    command = [f'sas{sas_version}ircu', '0', 'display']
    try:
        result = subprocess.run(
            command, 
            capture_output=True, 
            text=True, 
            errors='replace'
        )
    except Exception as e:
        print(f"Error running {' '.join(command)}: {e}")
        return []

    output = result.stdout
    sas_devices = []
    current_device = None

    for line in output.splitlines():
        if "Device is a Hard disk" in line:
            if current_device is not None:
                current_device["sas_version"] = sas_version
                sas_devices.append(current_device)
            current_device = {"serial": "", "guid": "", "enclosure": "", "slot": ""}
        elif current_device is not None:
            if "Enclosure #" in line and not current_device["enclosure"]:
                parts = line.split(":", 1)
                if len(parts) >= 2:
                    current_device["enclosure"] = parts[1].strip()
            if "Slot #" in line and not current_device["slot"]:
                parts = line.split(":", 1)
                if len(parts) >= 2:
                    current_device["slot"] = parts[1].strip()
            if ("Serial No" in line and "Unit Serial No" not in line) and not current_device["serial"]:
                parts = line.split(":", 1)
                if len(parts) >= 2:
                    current_device["serial"] = parts[1].strip()
            if "GUID" in line and not current_device["guid"]:
                parts = line.split(":", 1)
                if len(parts) >= 2:
                    current_device["guid"] = parts[1].strip()
    if current_device is not None:
        current_device["sas_version"] = sas_version
        sas_devices.append(current_device)
    return sas_devices

def get_sas_devices_parallel():
    """Run SAS commands in parallel"""
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_sas3 = executor.submit(get_sas_devices, "3")
        future_sas2 = executor.submit(get_sas_devices, "2")
        
    return future_sas3.result() + future_sas2.result()

def get_sas_devices_with_cache(drives):
    """Get SAS devices with hash-based caching support"""
    cache = load_cache()
    
    # Check if cache is valid based on state hash
    if is_cache_valid(cache, drives):
        print("Using cached SAS device information")
        return cache.get('sas_devices', [])
    
    sas_devices = get_sas_devices_parallel()
    
    save_cache(drives, sas_devices)
    
    return sas_devices

def populate_drives_sas_info(drives, sas_devices):
    """Match each drive to its SAS information."""
    for drive in drives:
        identifier = drive["wwn"] if drive["wwn"] else drive["serial"]
        norm_id = identifier.replace("-", "").lower() if identifier else ""
        for sas_dev in sas_devices:
            norm_guid = sas_dev.get("guid", "").replace("-", "").lower()
            if norm_id and norm_id == norm_guid:
                drive["enclosure"] = sas_dev.get("enclosure", "")
                drive["slot"] = sas_dev.get("slot", "")
                drive["sas_version"] = sas_dev.get("sas_version", "")
                break

def set_locator_light(drive, state):
    """
    Toggle the locator light for a drive.
    Uses either sas3ircu or sas2ircu command based on drive['sas_version'].
    """
    cmd = f'sas{drive["sas_version"]}ircu'
    action = "on" if state else "off"
    loc_arg = f"{drive['enclosure']}:{drive['slot']}"
    command = [cmd, "locate", loc_arg, action]
    try:
        subprocess.run(command, capture_output=True, text=True)
        #print(f"Turning SAS{drive['sas_version']}-{loc_arg} locator {action}")
        drive["locate"] = action
    except Exception as e:
        print(f"Error running {' '.join(command)}: {e}")

def update_locator_lights(drives, cache_was_valid=False, cached_devices=None):
    """
    Update the locator light based on drive status for all drives.
    Skip sending commands if the status hasn't changed from cached data.
    """
    # If we have a valid cache, add cached locate values to drives and optimize command sending
    if cache_was_valid and cached_devices:
        # Create maps for both status and locate from cache
        cached_drive_info = {}
        for drive in cached_devices.get('drives', []):
            if 'name' in drive:
                cached_drive_info[drive['name']] = {
                    'status': drive.get('status', ''),
                    'locate': drive.get('locate', '')
                }
        
        # First, add cached locate values to all drives for final output
        for drive in drives:
            cached_info = cached_drive_info.get(drive['name'], {})
            # Add the cached locate state to the drive object
            drive['locate'] = cached_info.get('locate', '')
        
        # Process drive lights based on status changes only
        for drive in drives:
            if not (drive.get("sas_version") and drive.get("enclosure") and drive.get("slot")):
                print(f"Skipping drive '{drive['name']}': no SAS info")
                continue
            
            # Check if status has changed - only use status for short-circuit decision
            previous_status = cached_drive_info.get(drive['name'], {}).get('status', None)
            current_status = drive["status"].upper()
            
            # Skip LED update command if status unchanged
            if previous_status and previous_status.upper() == current_status.upper():
                # Even when skipping the LED update, ensure the locate value matches current status
                drive['locate'] = 'off' if current_status in SAFE_DRIVE_STATUSES else 'on'
                continue
                
            # Update locator for drives with changed status
            if current_status in SAFE_DRIVE_STATUSES:
                set_locator_light(drive, state=False)
                print(f"Disabling indicator light for '{drive['name']}' at {drive['enclosure']}:{drive['slot']} updated state '{current_status}'")
            else:
                set_locator_light(drive, state=True)
                print(f"Enabling indicator light for '{drive['name']}' at {drive['enclosure']}:{drive['slot']} updated state '{current_status}'")
    else:
        # No valid cache, update all drives
        print("No valid cache, updating all drive indicator lights")
        for drive in drives:
            # Set the expected locate state based on drive status
            status = drive["status"].upper()
            drive['locate'] = 'off' if status in SAFE_DRIVE_STATUSES else 'on'
            
            if not (drive.get("sas_version") and drive.get("enclosure") and drive.get("slot")):
                print(f"Skipping drive '{drive['name']}': no SAS info")
                continue
            
            if status in SAFE_DRIVE_STATUSES:
                set_locator_light(drive, state=False)
            else:
                set_locator_light(drive, state=True)

if __name__ == '__main__':
    # Get a list of drives from ZFS
    drives = get_zpool_drives()

    # Get drive identifiers for each drive
    populate_drive_identifiers(drives)

    # Retrieve the enclosure and slot number for each drive
    cache = load_cache()
    cache_valid = is_cache_valid(cache, drives)

    if cache_valid:
        print("Using cached SAS device information")
        sas_devices = cache.get('sas_devices', [])
    else:
        sas_devices = get_sas_devices_parallel()
        save_cache(drives, sas_devices)

    populate_drives_sas_info(drives, sas_devices)

    # Update inidicator lights based on drive status
    update_locator_lights(drives, cache_was_valid=cache_valid, cached_devices=cache)

    # Print final state of the drives
    for drive in drives:
        print(drive)
