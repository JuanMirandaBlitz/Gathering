# Gathering

PowerShell script for gathering information on local systems

This script creates a folder called Results on the host desktop where
runs, then gathers information of applications installed on the host,
IP settings, routing tables, DNS cache, System users and groups, Current user,
vulnerable services and, finally, in case of having administration privileges will download the
Invoke-PowerDump script from its GitHub repository and will run it to do a hash dump.
