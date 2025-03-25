#!/usr/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Disable the fail/locator light on any connected SAS drives

disable_lights() {
    local version=$1
    local cmdlet="sas${version}ircu"
    
    if ! command -v $cmdlet >/dev/null 2>&1; then
        echo "$cmdlet not found, skipping SAS$version devices."
        return
    fi
    
    echo "Processing SAS$version devices..."
    
    # Variables to track current enclosure and device type
    local enclosure=""
    local slot=""
    local is_hard_disk=0
    
    # Process command output line by line
    $cmdlet 0 display 2>/dev/null | while IFS= read -r line; do
        # Check if this is a new device section
        if echo "$line" | grep -q "Device is a"; then
            # Reset variables for new device
            slot=""
            # Check if it's a hard disk
            if echo "$line" | grep -q "Hard disk"; then
                is_hard_disk=1
            else
                is_hard_disk=0
            fi
        fi
        
        if echo "$line" | grep -q "Enclosure #"; then
            enclosure=$(echo "$line" | sed -n 's/.*: *\([0-9][0-9]*\).*/\1/p')
        elif echo "$line" | grep -q "Slot #" && [ -n "$enclosure" ]; then
            slot=$(echo "$line" | sed -n 's/.*: *\([0-9][0-9]*\).*/\1/p')
            
            # Only process if it's a hard disk and we have valid enclosure and slot
            if [ $is_hard_disk -eq 1 ] && [ -n "$slot" ]; then
                echo "  - Turning off SAS$version location $enclosure:$slot"
                # Hide all output from the locate command
                $cmdlet 0 locate "$enclosure:$slot" OFF >/dev/null 2>&1
            fi
        fi
    done
}

echo "Turning off SAS drive locator lights..."

# Process both SAS controllers
disable_lights 2
disable_lights 3

echo "All locator lights have been turned off."