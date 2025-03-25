# ZFS-Drive-Identify
Set SAS drive identification lights from ZFS disk failures

This application has only been tested against TrueNAS Scale on a SuperMicro Backplane using an LSI HBA. Different combinations of SAS hardware and different OS utilities may result in unexpected behavior.

# Features
- Monitors all drives added to a ZFS Pool.
- Uses minimal system resources and does not spam the HBA with unnecessary commands.
- Works with both SAS3 and SAS2 backplanes.

# Limitations
- Supports a single SAS3 HBA and a single SAS2 HBA at once. (controller id 0)

# Installation
- Place all files onto the local filesystem of the appliance.
- Make sure to set the script as executable: `chmod +x identify.py`
- Call the script using a cron entry, for example every 5 minutes: "*/5 * * * * /root/identify.py"

# Troubleshooting:
- Delete the cache file stored at: `/tmp/zfs_sas_device_cache.json`
- Run the script manually to review any error messages
- Run the cron as root