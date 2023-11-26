<#
.SYNOPSIS
Deploys a package of chosen threat hunting/DFIR tools (cargo.zip) and the accompanying install script (package_installer.ps1) to multiple computers specified in a text file called "computers.txt".

.DESCRIPTION
The script performs the following tasks:
1. Sets several global variables such as the username, source directory, and file location of the computers.txt file.
2. Uses the Get-ADComputer cmdlet to gather information about the target computers including their DNS hostname, whether they are enabled, their last logon date, IP addresses, operating system, and service pack.
3. Outputs just names of the target computers to the computers.txt file.
4. Reads the contents of the computers.txt file and assigns them to the $computerNames variable.
5. Enables remote PowerShell execution on the local and target computers and prompts the user for their credentials.
6. Sets a WinRM session timeout of 200000 seconds.
7. Starts a loop that iterates through each computer specified in the $computerNames variable.
8. Inside the loop, attempts to open a remote PowerShell session on the target computer using the New-PSSession cmdlet.
9. Checks the version of PowerShell on the target computer and if it is greater than or equal to version 4, copies the deployment package (cargo.zip) and the package_installer.zip to the C:\Windows\Temp directory on the target computer using the Copy-Item cmdlet.
10. Runs a series of survey commands on the target computer using the Invoke-Command cmdlet.
11. The survey gathers information about the target computer including the hostname, operating system version, CPU architecture, and PowerShell version.
12. Runs several system commands such as Get-LocalGroupMember, net user, systeminfo, gpupdate, and gpresult.
13. If the deployment package successfully copied to the endpoint and there is enough space on the target computer for installation, runs the package installer script (package_installer.ps1), then removes the deployment package and other files after installation.
14. Attempts to delete two scheduled tasks created by Aurora.
15. Runs the previous commands as a job so that it can run multiple jobs in parallel across all machines rapidly.

.NOTES
Author: SEER
Date: 04/08/2022
Version: 1.1

For reverse compatibility with 32 bit Win7 systems, uncomment Register-PSSessionConfiguration microsoft.powershell32 -ProcessorArchitecture x86 -Force

ACTIVE DIRECTORY DUMP COMMANDS
# This command gets information about all computers in the domain and exports it to a CSV file.
get-adcomputer -Filter * -properties dnshostname, enabled, lastlogondate, ipv4address, operatingsystem, operatingsystemservicepack | export-csv -Path C:\users\administrator\Documents\deployment_package\machines.csv #out-gridview

# This command gets information about all enabled users in the domain and exports it to a CSV file.
Get-ADUser -Filter {enabled -eq $true} -Property created,lastlogondate | Select-Object -Property name, samaccountname, created, lastlogondate, sid | export-csv -Path C:\users\administrator\Documents\deployment_package\users.csv

# This command gets information about all members of the domain admins group and exports it to a CSV file.
Get-ADGroupMember 'domain admins' | export-csv -path C:\users\administrator\Documents\deployment_package\domain_admins.csv

#TO SIGN THE SCRIPT (example):
New-SelfSignedCertificate -subject "ATA Authenticode" -CertStoreLocation cert:\localmachine\my -type CodeSigningCert
$codecertificate= gci cert:\localmachine\my | Where-Object {$_.Subject -eq "CN=ATA Authenticode"}
Set-AuthenticodeSignature C:\users\$user\Documents\deployment_package\lightweight_push_and_run.ps1 $codecertificate 

#>

#LEGEND:
#MP = Mission Partner (the customer)

# This section prompts the user to complete a pre-deployment checklist.
Read-Host -Prompt "A Pre-Deployment checklist. We recommend using it"
Read-Host -Prompt "Has the beats config been updated to point to the correct kit IP? If not, CNTRL+C NOW"
Read-Host -Prompt "Has the beats config been updated to pull at least the last 30 days of logs? If not, CNTRL+C NOW"
Read-Host -Prompt "Have you imported and linked the {A22F621A-10F9-4CA3-9798-9730AB750EB6} audit policy? If not, CNTRL+C NOW"
Read-Host -Prompt "Has the Thor and Aurora licences been supplied and sanitized of attrib? If not, CNTRL+C NOW"
Read-Host -Prompt "Have you queried the AD and generated a list of machines in computers.txt? If not, CNTRL+C NOW"
Read-Host -Prompt "Has the MP AUTHORIZED your computers listing? If not, CNTRL+C NOW"
Read-Host -Prompt "Have you completed rigorous testing on a variety of machines with consent of the MP? If not, CNTRL+C NOW"
Read-Host -Prompt 'Has the installer.ps1 $sourcedir variable been updated to pull from C:\windows\temp\powershell_deploy or a relevant SYSVOL location? If not, CNTRL+C NOW'
Read-Host -Prompt "Has a decision been made to incude a stand-alone Endgame binary inside the cargo.zip archive for in-band deployment? Have you updated the binary key variable? If not, CNTRL+C NOW"
Read-Host -Prompt "Have you updated the Win7 endpoints to WMF 5.1 and powershell 5.1? If not this will fail."

Write-Host "Initiating WinRM deployment"

$current_user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split('\')[1]
# Sets the global variable 'user' to '$current_user'
Set-Variable -Name 'user' -Value ("$current_user") -Scope global -PassThru | Out-Null
# Sets the global variable 'source_dir' to the path of the deployment package.
Set-Variable -Name 'source_dir' -Value ("C:\Users\$user\Documents\deployment_package\") -Scope global -PassThru | Out-Null
# Sets the path of the computers.txt file.
$computers_file = "C:\Users\$user\Documents\deployment_package\computers.txt"
# Checks if the computers.txt file exists before attempting to read its contents.
if (Test-Path $computers_file) {
    # Reads the contents of the computers.txt file and assigns them to the $iterative variable.
    $iterative = Get-Content $computers_file
} else {
    Write-Host "The computers.txt file does not exist."
    Exit
}
# Sets the global variable 'installjoblog' to the path of the InstallJobLog.txt file.
Set-Variable -Name 'installjoblog' -Value ("C:\Users\$user\Documents\deployment_package\InstallJobLog.txt") -Scope global -PassThru | Out-Null 
# Enables remote PowerShell execution on the local and target computers and prompts the user for their credentials.
Enable-PSRemoting -SkipNetworkProfileCheck -Force
$cred = Get-Credential
# Sets the global variable 'session_timeout' to a WinRM session timeout of 200000 seconds.
Set-Variable -Name 'session_timeout' -Value (New-PSSessionOption -IdleTimeout 200000) -Scope global -PassThru | Out-Null

# Prompts the user to update Thor/Aurora signatures and upgrade binaries.
$response = Read-Host "Update Thor/Aurora signatures and upgrade binaries? (Y/N)"
if (($response -eq "Y") -and (Test-Connection -ComputerName "www.google.com" -Count 1)) {
    Write-Host "Updating..."
    iex "$source_dir\cargo\aurora-agent-lite-win-pack\aurora-agent-util.exe update"
    iex "$source_dir\cargo\aurora-agent-lite-win-pack\aurora-agent-util.exe upgrade"
    iex "$source_dir\cargo\thor10.7lite-win-pack\thor-lite-util.exe update"
    iex "$source_dir\cargo\thor10.7lite-win-pack\thor-lite-util.exe upgrade"
} elseif ($response -eq "N") {
} else {
    Write-Host "No internet connectivity or invalid response."
}

# Removes the old deployment package and creates a new one.
Remove-Item "$source_dir\powershell_deploy\cargo.zip" -ErrorAction SilentlyContinue
if (Test-Path "$source_dir\cargo\*") {
    Compress-Archive -Path "$source_dir\cargo\*" -DestinationPath "$source_dir\powershell_deploy\cargo.zip"
} else {
    Write-Host "The cargo directory does not exist."
    Exit
}

# Loops through each computer specified in the $iterative variable.
ForEach ($computer in $iterative) {
    # Attempts to open a remote PowerShell session on the target computer using the New-PSSession cmdlet.
    Write-Host ("Attempting to open WINRM session on $computer")
    try {
        $session = New-PSSession -ComputerName $computer -Credential $cred -SessionOption $session_timeout -ErrorAction Stop
    } catch {
        Write-Host "Failed to open WINRM session on $computer"
        continue
    }
    # Checks the version of PowerShell on the target computer and if it is greater than or equal to version 4, it copies the deployment package (cargo.zip) and the package_installer.zip to the C:\Windows\Temp directory on the target computer using the Copy-Item cmdlet.
    $powershellversioncheck = Invoke-Command -Session $session -ScriptBlock { $PSVersionTable.PSVersion }
    if ($powershellversioncheck.major -ge 4) {
        if (Test-Path "$source_dir\powershell_deploy\cargo.zip") {
            Copy-Item -Path "$source_dir\powershell_deploy" -Destination 'C:\Windows\Temp' -ToSession $session -Recurse -Force
        } else {
            Write-Host "The deployment package does not exist."
            Exit
        }
    }
    # Runs a series of survey commands on the target computer using the Invoke-Command cmdlet.
    Invoke-Command -Session $session -ScriptBlock {
        # For machine tagging when reviewing joblog.txt.
        $insidejobtagging = hostname
        # Starts the survey.
        $OSVersion = [Environment]::OSVersion.Version.Major
        $CPU_Arch = (Get-WmiObject CIM_OperatingSystem).OSArchitecture
        echo "MACHINE NAME $insidejobtagging OS=$OSVersion"
        echo "CPU Arch is $CPU_Arch"
        echo "Powershell version is...." $PSVersionTable.PSVersion.Major
        powershell -executionpolicy bypass -windowstyle hidden -command "Get-LocalGroupMember -Group 'Administrators'; net user; systeminfo; gpupdate /force; gpresult /r"
        # If the deployment package successfully copied to the endpoint and there is enough space on the target computer for installation, it runs the package installer script (package_installer.ps1), then removes the deployment package and other files after installation.
        if ((Test-Path -Path 'C:\Windows\Temp\powershell_deploy') -and (Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'" | ? { $_.FreeSpace -ge 900MB })) {
            powershell -windowstyle hidden -executionpolicy bypass -f 'C:\Windows\Temp\powershell_deploy\package_installer.ps1'
            #powershell -windowstyle hidden -executionpolicy bypass -f 'C:\Windows\Temp\powershell_deploy\package_uninstaller.ps1'
            remove-item -recurse -force 'C:\Windows\Temp\powershell_deploy'
            remove-item -recurse -force 'C:\programdata\winsys\package_installer.ps1'
            remove-item -recurse -force 'C:\programdata\winsys\package_uninstaller.ps1'
            #schtasks /delete /f /tn appupdater-program-update # I really hated having to add these two lines, but at the time of writing, there was no other way to remove those loud schtasks that auroura creates 
            #schtasks /delete /f /tn appupdater-signature-update 
        }
        # This is for win7 machines to activate their startup scripts, assuming that has been configured in the group policy. Restart timer is set for 8 hours(32400 is in seconds) hours from time of execution, which should be a period in which the user is not present in most scenarios.
        $OSVersion = [Environment]::OSVersion.Version.Major
        #if  ($OSVersion -eq 6) {
        #echo "Win 7 or 8 based OS detected. Restarting to invoke start-up script"
        #shutdown /r /t 5} #32400 for 8 hours
        # Optional capability to execute thor-lite scans against hosts identified inside of computers.txt. Make sure IP is updated to actual KIT IP.
        #Invoke-expression 'C:\ProgramData\WinSys\thor10.7lite-win-pack\thor64-lite.exe --nolog -s <KIT IP>:<PORT>:SYSLOGJSON:TCP --maxsysloglength 0'
    } -AsJob -JobName "deployinstall$computer" # Comment this line just after the }, to remain inside sessions and recieve output of script for troubleshooting/testing. This will significantly slow the deployment process.
    Write-Host ("Done with $computer. Looping to the next machine ")
    # Writes the output of the job to the InstallJobLog.txt file.
    Get-Job -State Completed -HasMoreData $true | Receive-Job *>&1 >> $installjoblog
} 

# This portion of code uses a while loop to scan all the jobs running, and immediately after they change status from 'running' to 'complete', pipes all the events that occurred inside that job to our installjoblog.txt. 
# This allows us to observe and troubleshoot any error encountered on the endpoints. A significant advantage of a powershell deployment. 
while ((Get-Job -State Completed -HasMoreData $true) -or (Get-Job -State Running)) { Get-Job -State Completed -HasMoreData $true | Receive-Job *>&1 >> $installjoblog }

# This portion performs post-processing on installjoblog.txt and cuts out everything except the successful or failed install of each agent and pipes it to a separate exit_codes.txt. 
# Serves as a straight to the point agent observation log.
Set-Variable -Name 'install_check' -Value (Select-String -Path $InstallJobLog -Pattern "INSTALL OF") -Scope global -PassThru | Out-Null
echo $install_check >> "C:\Users\$user\Documents\deployment_package\exit_codes.txt"
Remove-PSSession *
