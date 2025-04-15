# teams4AVD
teams4AVD is a PowerShell script designed to automate the installation of the new Microsoft Teams optimized for Azure Virtual Desktop (AVD) environments. This script not only installs Teams but also handles the optional uninstallation of the previous Teams version and the Teams Meeting Add-in, installs necessary dependencies such as Visual C++ Redistributables and WebRTC, and configures required registry settings.

# Features
Optional Uninstallation: Choose to remove the old Teams version and its associated Teams Meeting Add-in.
Dependency Installation: Automatically downloads and installs Visual C++ Redistributable (x86 and x64) and WebRTC.
Optimized Installation: Installs the latest Teams build optimized for AVD.
Add-In Configuration: Installs and verifies the Microsoft Teams Meeting Add-in for Outlook with the correct installation path.
FSLogix Verification: Checks that FSLogix is installed and meets the required minimum version.
Prerequisites
Administrator Privileges: Run the script with elevated privileges (PowerShell as Administrator).
FSLogix: Ensure that FSLogix is installed and updated to at least version 2.9.8884.27471.
Internet Access: The script downloads necessary files from the Internet.
