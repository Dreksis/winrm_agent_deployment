# Rapid peer-to-peer agent deployments via WinRM. 
## Developed for threat hunting teams desiring low visibility and reduced risk of attribution in non-permissive domains.

## lightweight_push_and_run.ps1

A simple powershell script designed to deploy a compressed package of tools/agents, perform a quick survey, and install agents/tools on multiple computers specified in a file named computers.txt. The script establishes a remote PowerShell session to each computer and performs various operations such as copying files, installing agents, and gathering basic survey information.

It is designed to be lightweight/minimal, to facilitate quick troubleshooting during threat hunting engagements.

![alt text](https://github.com/Dreksis/powershell_agent_deployment/blob/main/deployment_package/Powershell%20Deployment%20flow%20diagram.PNG)


## Requirements
- Windows operating system with PowerShell 4.0 or later installed
- Access to a file named computers.txt containing a list of computer names or IP addresses
- A valid set of credentials for establishing remote PowerShell sessions
- The cargo directory must be zipped and placed in the \powershell_deploy directory

## Contents of deployment_package\
- This is a sanitized deployment_package. All of the below have been removed except for lightweight_push_and_run.ps1 and Powershell Deployment flow diagram.png
- **{A22F621A-10F9-4CA3-9798-9730AB750EB6}**  This is the group policy that facilitates the WinRM deployment across the domain. Provides WinRM enablements and an enhanced audit policy. It is based off of Palantir's open source "Enhanced Logging" policy. {A22F621A-10F9-4CA3-9798-9730AB750EB6} must be imported and linked to the domain prior to deployment.
- **cargo** This is a container for the agents, software, and capabilities that will be deployed. It is meant to be tailored to the threat hunting team's requirements.
- **licenses** This is a convenience container to hold unattributable licenses for Aurora and Thor. They must be independently moved to the aurora and thor folders respectively prior to deployment.
- **powershell_deploy** This directory is what will be copied to each endpoint during the deployment. It contains package_installer.ps1 and the cargo directory in a compressed .zip. The cargo directory will automatically be compressed and transferred to this directory as cargo.zip on execution of lightweight_push_and_run.ps1
- **lightweight_push_and_run.ps1** Deployment script. Pushes contents of powershell_deploy to each endpoint and starts the installation process of agents. Each endpoint is executed as a WinRM session job for speed and efficiency
- **Powershell Deployment flow diagram.png** A simple flow chart to illustrate the deployment process.


## Usage
- Link the {A22F621A-10F9-4CA3-9798-9730AB750EB6} group policy to the domain or respective OU.
- Update the variables in package_installer.ps1 to match your environment and agent configuration.
- Generate the host names of endpoints for deployment and list them in computers.txt. 
- Run the script as an administrator.


## Logs
- A log file named InstallJobLog.txt is created in the user's documents folder to keep track of the operations performed on each computer.
- A log file named exitcodes.txt provides a quick snapshot of install success or failure of each agent from each endpoint.

## Notes
- The script assumes that the deployment package is located in a users documents folder.
- **DO NOT PEFORM A DOMAIN WIDE DEPLOYMENT WITHOUT FIRST TESTING ON A VARIETY OF ENDPOINTS** 

## Why Powershell/WinRM?:

- Speed
- Target specific machines for deployment
- Receive job information for troubleshooting
- Ideal choice for deployment in smaller domains.

The deployment of agents through WinRM provides several key benefits, particularly its ability to target specific machines and receive job information. This capability is especially important for troubleshooting and makes WinRM an ideal choice for deployment in a domain.

WinRM's machine targeting ability enables administrators to deploy agents to specific machines, making it easier to manage and troubleshoot the deployment. This capability is especially useful in large domains, where deploying agents to every machine may not be necessary. By targeting specific machines, administrators can focus their deployment efforts on the most critical systems, reducing the time and effort required to deploy agents to every machine in the domain.

WinRM deployments WILL be faster for targeted deployments, as they allow administrators to deploy software to specific machines without the overhead of a centralized management system. This can be particularly useful when deploying updates or fixes to a small number of machines. Additionally, group policy requires specific execution triggers configured to install agents, such as scheduled tasks or even more annoying.......a domain wide reboot of endpoints via gpo startup scripts. 

In addition, WinRM's ability to receive job information is crucial for troubleshooting and resolving deployment issues. This information can help administrators quickly identify and resolve any problems that may arise during the deployment, making the process smoother, more efficient, reducing downtime, and ensuring that agents are deployed and functioning as intended.

## Why Group Policy?:

- Ensures deployment is successful for all machines
- Deploys agents to offline machines
- Provides added reliability and consistency

When deploying agents through WinRM, the deployment will only be successful for machines that are online and reachable at the time of the deployment. Any machines that are offline will not receive the deployment, leaving them unprotected/umonitored.

In contrast, deploying agents through group policy ensures that the deployment is successful for all machines, regardless of whether they were online during the WinRM deployment. When a machine that was offline during a WinRM deployment comes online, it will receive the deployment through group policy, ensuring that it is protected and configured consistently with the rest of the endpoints in the domain.

## The 'Dual Vector' method:

- Faster initial deployment gain using WinRM
- Job/session feedback for troubleshooting
- Centralized management and security enforcement using Group Policy
- Ensures successful deployment to all machines
- Maximum protection and consistency for the network
- Provides a flexible and powerful solution for deploying and managing agents in a domain.

Using BOTH WinRM and Group Policy for agent deployment offers synergistic benefits, resulting in a comprehensive and efficient solution. WinRM allows for targeted deployment and troubleshooting, while Group Policy provides centralized management, security enforcement, and deployment capability to machines with unpredictable power cycles. This combination ensures successful deployment to all machines and maximum protection and consistency for the network. The use of both tools provides a flexible and powerful solution for deploying and managing agents in a domain.

