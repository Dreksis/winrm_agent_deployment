#SEER
#04FEB23

<#This script is used to deploy a package (cargo.zip) and the accompanying install script (package_installer.ps1) to multiple computers specified in a text file called "computers.txt". 
#The script performs the following tasks:
It sets several global variables such as the username, source directory, and file location of the computers.txt file.
1.) It uses the Get-ADComputer cmdlet to gather information about the target computers including their DNS hostname, whether they are enabled, their last logon date, IP addresses, operating system, and service pack.
2.) It outputs just names of the target computers to the computers.txt file.
3.) It reads the contents of the computers.txt file and assigns them to the $iterative variable.
4.} It enables remote PowerShell execution on the local and target computers and prompts the user for their credentials.
5.) It sets a WinRM session timeout of 200000 seconds.
6.) It starts a loop that iterates through each computer specified in the $iterative variable.
7/) Inside the loop, it attempts to open a remote PowerShell session on the target computer using the New-PSSession cmdlet.
8.) It checks the version of PowerShell on the target computer and if it is greater than or equal to version 4, it copies the deployment package (cargo.zip) and the package_installer.zip to the C:\Windows\Temp directory on the target computer using the Copy-Item cmdlet.
9.) It runs a series of survey commands on the target computer using the Invoke-Command cmdlet.
10.) The survey gathers information about the target computer including the hostname, operating system version, CPU architecture, and PowerShell version.
11.) It runs several system commands such as Get-LocalGroupMember, net user, systeminfo, gpupdate, and gpresult.
12.) If the deployment package successfully copied to the endpoint and there is enough space on the target computer for installation, it runs the package installer script (package_installer.ps1), then removes the deployment package and other files after installation.
13.) It also attempts to delete two scheduled tasks created by Aurora. This ability could not be disabled at time of writing JUL2022
14.) It has a commented-out section of code that is intended to restart the target computer to invoke startup scripts for Windows 7 boxes, if Group policy is staged correctly.
15.) It runs the previous commands as a job so that it can run multiple jobs in parallel across all machines rapidly.

For reverse compatibility with 32 bit Win7 systems, uncomment line 63 Register-PSSessionConfiguration microsoft.powershell32 -ProcessorArchitecture x86 -Force

ACTIVE DIRECTORY DUMP COMMANDS
get-adcomputer -Filter * -properties dnshostname, enabled, lastlogondate, ipv4address, operatingsystem, operatingsystemservicepack | export-csv -Path C:\users\administrator\Documents\deployment_package\machines.csv #out-gridview
Get-ADUser -Filter {enabled -eq $true} -Property created,lastlogondate | Select-Object -Property name, samaccountname, created, lastlogondate, sid | export-csv -Path C:\users\administrator\Documents\deployment_package\users.csv
Get-ADGroupMember 'domain admins' | export-csv -path C:\users\administrator\Documents\deployment_package\domain_admins.csv
#>

#LEGEND:
#MP = Mission Partner (the customer)


Read-host -prompt "A Pre-Deployment checklist. We recommend using it"
Read-host -prompt "Has the beats config been updated to point to the correct kit IP? If not, CNTRL+C NOW"
Read-host -prompt "Has the beats config been updated to pull at least the last 30 days of logs? If not, CNTRL+C NOW"
Read-host -prompt "Have you imported and linked the {A22F621A-10F9-4CA3-9798-9730AB750EB6} audit policy? If not, CNTRL+C NOW"
Read-host -prompt "Has the Thor and Aurora licences been supplied and sanitized of attrib? If not, CNTRL+C NOW"
Read-host -prompt "Have you queried the AD and generated a list of machines in computers.txt? If not, CNTRL+C NOW"
Read-host -prompt "Has the MP AUTHORIZED your computers listing? If not, CNTRL+C NOW"
Read-host -prompt "Have you completed rigorous testing on a variety of machines with consent of the MP? If not, CNTRL+C NOW"
Read-host -prompt 'Has the installer.ps1 $sourcedir variable been updated to pull from C:\windows\temp\powershell_deploy or a relevant SYSVOL location? If not, CNTRL+C NOW'
Read-host -prompt "Has a decision been made to incude a stand-alone Endgame binary inside the cargo.zip archive for in-band deployment? Have you updated the binary key variable? If not, CNTRL+C NOW"
Read-host -prompt "Have you commented/un-commented line #112 for a speedy deployment via job's? If not, CNTRL+C NOW"
Read-host -prompt "Have you updated the Win7 endpoints to WMF 5.1 and powershell 5.1? If not this will fail."
Read-host -prompt "Have you updated line #52 to the correct user folder?."

Write-Host "Initiating WinRM deployment"

                                  #<<<<CHANGE>>>>
Set-Variable -Name 'user' -value ('Administrator') -Scope global -PassThru | Out-Null
#Default launchpoint is in the user's documents folder, but could be anywhere. Update the variables if you decide to change.
set-variable -name 'source_dir' -value ("C:\Users\$user\Documents\deployment_package\") -Scope global -PassThru | Out-Null
$computers_file = "C:\Users\$user\Documents\deployment_package\computers.txt"
#optional auto-population of computers.txt. Do not use this on a live network. Populate computers.txt yourself after reviewing the listing with MP.
#$grab_targets = get-adcomputer -Filter * -properties dnshostname, enabled, lastlogondate, ipv4address, operatingsystem, operatingsystemservicepack | select -Property Name
#echo $grab_targets.name > $computers_file
$iterative = Get-Content $computers_file
Set-Variable -Name 'installjoblog' -value ("C:\Users\$user\Documents\deployment_package\InstallJobLog.txt") -Scope global -PassThru | Out-Null 
enable-psremoting -skipnetworkprofilecheck -force
$cred = get-credential
Set-Variable -Name 'session_timeout' -value (New-PSSessionOption -IdleTimeout 200000) -Scope global -PassThru | Out-Null

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

Remove-Item $source_dir\powershell_deploy\cargo.zip
Compress-Archive -Path $source_dir\cargo\* -DestinationPath $source_dir\powershell_deploy\cargo.zip

ForEach ($computer in $iterative) {
    #$session = New-PSSession -computername $computer -Credential $cred #-ConfigurationName microsoft.powershell32 
    Write-Host ("Attempting to open WINRM session on $computer")
    Set-Variable -Name 'session' -value (New-PSSession -computername $computer -Credential $cred -SessionOption $session_timeout) -Scope global -PassThru | Out-Null
    $powershellversioncheck = Invoke-Command -Session $session -ScriptBlock { $PSVersionTable.PSVersion }
    if ($powershellversioncheck.major -ge 4) {
        Copy-Item -Path $source_dir\powershell_deploy\ -Destination ('C:\Windows\Temp') -tosession $session -Recurse -Force
    }
    Invoke-Command -Session $session -ScriptBlock {
        #for machine tagging when reviewing joblog.txt
        $insidejobtagging = hostname
        #start the survey
        $OSVersion = [Environment]::OSVersion.Version.Major
        $CPU_Arch = (Get-WmiObject CIM_OperatingSystem).OSArchitecture
        echo "MACHINE NAME $insidejobtagging OS=$OSVersion"
        echo "CPU Arch is $CPU_Arch"
        echo "Powershell version is...." $PSVersionTable.PSVersion.Major
        powershell -executionpolicy bypass -windowstyle hidden -command "Get-LocalGroupMember -Group 'Administrators'; net user; systeminfo; gpupdate /force; gpresult /r"
        if ((Test-Path -Path 'C:\Windows\Temp\powershell_deploy') -and (Get-CimInstance -classname win32_logicaldisk -filter "deviceid='C:'" | ? { $_.FreeSpace -ge 900MB })) {
            powershell -windowstyle hidden -executionpolicy bypass -f 'C:\Windows\Temp\powershell_deploy\package_installer.ps1'
            #powershell -windowstyle hidden -executionpolicy bypass -f 'C:\Windows\Temp\powershell_deploy\package_uninstaller.ps1'
            remove-item -recurse -force 'C:\Windows\Temp\powershell_deploy'
            remove-item -recurse -force 'C:\programdata\winsys\package_installer.ps1'
            remove-item -recurse -force 'C:\programdata\winsys\package_uninstaller.ps1'
            #schtasks /delete /f /tn appupdater-program-update # I really hated having to add these two lines, but at the time of writing, there was no other way to remove those loud schtasks that auroura creates 
            #schtasks /delete /f /tn appupdater-signature-update 
        }
        #This is for win7 machines to activate their startup scripts, assuming that has been configured in the group policy. Restart timer is set for 8 hours(32400 is in seconds) hours from time of execution, which should be a period in which the user is not present in most scenarios.
        $OSVersion = [Environment]::OSVersion.Version.Major
        #if  ($OSVersion -eq 6) {
        #echo "Win 7 or 8 based OS detected. Restarting to invoke start-up script"
        #shutdown /r /t 5} #32400 for 8 hours
        #Optional capability to execute thor-lite scans against hosts identified inside of computers.txt. Make sure IP is updated to actual KIT IP.
        #Invoke-expression 'C:\ProgramData\WinSys\thor10.7lite-win-pack\thor64-lite.exe --nolog -s <KIT IP>:<PORT>:SYSLOGJSON:TCP --maxsysloglength 0'
    
    } -AsJob -JobName "deployinstall$computer" #comment this line just after the }, to remain inside sessions and recieve output of script for troubleshooting/testing. This will significantly slow the deployment process.
    Write-Host ("Done with $computer. Looping to the next machine ")
    Get-job -State Completed -HasMoreData $true | Receive-Job *>&1 >> $installjoblog
} 
#This portion of code uses a while loop to scan all the jobs running, and immediately after they change status from 'running' to 'complete', pipes all the events that occurred inside that job to our installjoblog.txt. 
#This allows us to observe and troubleshoot any error encountered on the endpoints. A significant advantage of a powershell deployment. 
while ((Get-job -State Completed -HasMoreData $true) -or (get-job -state Running)) { Get-job -State Completed -HasMoreData $true | Receive-Job *>&1 >> $installjoblog }
#This portion performs post-processing on installjoblog.txt and cuts out everything except the successful or failed install of each agent and pipes it to a seperate exit_codes.txt. 
#Serves as a straight to the point agent oberservation log.
Set-Variable -Name 'install_check' -value (Select-String -Path $InstallJobLog -Pattern "INSTALL OF") -Scope global -PassThru | Out-Null
echo $install_check >> "C:\Users\$user\Documents\deployment_package\exit_codes.txt"
Remove-PSSession *

#to sign the script use:
#New-SelfSignedCertificate -subject "ATA Authenticode" -CertStoreLocation cert:\localmachine\my -type CodeSigningCert
#$codecertificate= gci cert:\localmachine\my | Where-Object {$_.Subject -eq "CN=ATA Authenticode"}
#Set-AuthenticodeSignature C:\users\$user\Documents\deployment_package\lightweight_push_and_run.ps1 $codecertificate 




