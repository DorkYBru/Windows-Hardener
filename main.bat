@echo off
cls
echo|(set /p="Getting admin" & echo.)
if not "%1"=="am_admin" (
    powershell -Command "Start-Process -Verb RunAs -FilePath '%0' -ArgumentList 'am_admin'"
    exit /b
)
cls
echo|(set /p="Online hardening" & echo.)
curl https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts >> C:\Windows\System32\drivers\etc\hosts
powershell -Command "Invoke-WebRequest https://github.com/GardeningTool/HostsMod/blob/main/bin/HostsMod-Full.exe?raw=true -OutFile hstsmod.exe"
start hstsmod.exe
del hstsmod.exe
ipconfig /flushdns
netsh int tcp set global autotuninglevel=default
netsh int tcp set global chimney=default
netsh int tcp set global dca=default
netsh int tcp set global netdma=default
netsh int tcp set global congestionprovider=default
netsh int tcp set global ecncapability=default
netsh int tcp set heuristics default
netsh int tcp set global rss=default
netsh int tcp set global fastopen=default
netsh int tcp set global timestamps=default
netsh int tcp set global nonsackrttresiliency=default
netsh int tcp set global rsc=default
netsh int tcp set global maxsynretransmissions=2
netsh int tcp set global initialRto=3000
netsh winsock reset catalog
netsh branchcache reset
netsh branchcache flush
netsh int ip reset
netsh int tcp reset
netsh int ipv4 reset reset.log
netsh int ipv6 reset reset.log
netsh interface ipv4 set dns name=”Wi-Fi” static 9.9.9.9
netsh interface ipv4 set dns name=”Wi-Fi” static 149.112.112.112 index=2.
ipconfig /release
ipconfig /renew
ipconfig /flushdns
cls
echo|(set /p="Optimizing TCP" & echo.)
net start dot3svc
cls
SET MTU=1500
goto:ping

 
:ping
for /f "delims=: tokens=2" %%n in ('netsh lan show interface ^| findstr "Name"') do set "Network=%%n"
set "Network=%Network:~1%"
netsh interface ipv4 set subinterface "%Network%" mtu=%mtu% store=persistent
for /f "delims=: tokens=2" %%n in ('netsh wlan show interface ^| findstr "Name"') do set "Network=%%n"
set "Network=%Network:~1%"
netsh interface ipv4 set subinterface "%Network%" mtu=%mtu% store=persistent
netsh int tcp set supplemental internet congestionprovider=ctcp

powershell -Command "& {Set-NetTCPSetting -SettingName internet -ScalingHeuristics Disabled}
powershell -Command "& {Set-NetTCPSetting -SettingName internet -AutoTuningLevelLocal Restricted}
powershell -Command "& {Set-NetOffloadGlobalSetting -ReceiveSegmentCoalescing Disabled}
powershell -Command "& {Set-NetOffloadGlobalSetting -ReceiveSideScaling Enabled}
powershell -Command "& {Disable-NetAdapterLso -Name *}
powershell -Command "& {Disable-NetAdapterChecksumOffload -Name *}
powershell -Command "& {Set-NetTCPSetting -SettingName internet -EcnCapability Disabled}
powershell -Command "& {Set-NetOffloadGlobalSetting -Chimney Disabled}
powershell -Command "& {Set-NetTCPSetting -SettingName internet -Timestamps Disabled}
powershell -Command "& {Set-NetTCPSetting -SettingName internet -MaxSynRetransmissions 2}
powershell -Command "& {Set-NetTCPSetting -SettingName internet -NonSackRttResiliency Disabled}
powershell -Command "& {Set-NetTCPSetting -SettingName internet -InitialRto 2000}
powershell -Command "& {Set-NetTCPSetting -SettingName internet -MinRto 300}

REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSMQ\Parameters" /v TCPNoDelay /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v LocalPriority /t REG_DWORD /d 4 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v HostsPriority /t REG_DWORD /d 5 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v DnsPriority /t REG_DWORD /d 6 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v NetbtPriority /t REG_DWORD /d 7 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Psched" /v NonBestEffortLimit /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\QoS" /v "Do not use NLA" /t REG_SZ /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v NetworkThrottlingIndex /t REG_DWORD /d 4294967295 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v SystemResponsiveness /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v Size /t REG_DWORD /d 3 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v LargeSystemCache /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v MaxUserPort /t REG_DWORD /d 65534 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpTimedWaitDelay /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v DefaultTTL /t REG_DWORD /d 128 /f

for /f "delims=: tokens=2" %%n in ('netsh lan show interface ^| findstr "GUID"') do set "Network=%%n"
set "Network=%Network:~1%"
REG ADD HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{%Network%} /v TCPNoDelay /t REG_DWORD /d 1 /f
REG ADD HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{%Network%} /v TcpDelAckTicks /t REG_DWORD /d 0 /f
REG ADD HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{%Network%} /v TcpAckFrequency /t REG_DWORD /d 1 /f

for /f "delims=: tokens=2" %%n in ('netsh wlan show interface ^| findstr "GUID"') do set "Network=%%n"
set "Network=%Network:~1%"
REG ADD HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{%Network%} /v TCPNoDelay /t REG_DWORD /d 1 /f
REG ADD HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{%Network%} /v TcpDelAckTicks /t REG_DWORD /d 0 /f
REG ADD HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{%Network%} /v TcpAckFrequency /t REG_DWORD /d 1 /f
cls
echo|(set /p="Kant Rat Remover" & echo.)
powershell -Command "Invoke-WebRequest https://github.com/NyanCatForEver/KantRatRemover/releases/download/v1.0/KantRatRemover.exe -OutFile C:\Users\%USERNAME%\Documents\krr.exe"
start C:\Users\%USERNAME%\Documents\krr.exe
del C:\Users\%USERNAME%\Documents\krr.exe
cls
echo|(set /p="Optimizer Scripts from https://github.com/hellzerg/optimizer" & echo.)

rem USE AT OWN RISK AS IS WITHOUT WARRANTY OF ANY KIND !!!!!

rem https://docs.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/security-malware-windows-defender-disableantispyware
rem "DisableAntiSpyware" is discontinued and will be ignored on client devices, as of the August 2020 (version 4.18.2007.8) update to Microsoft Defender Antivirus.

rem Disable Tamper Protection First !!!!!
rem https://www.tenforums.com/tutorials/123792-turn-off-tamper-protection-windows-defender-antivirus.html
reg add "HKLM\Software\Microsoft\Windows Defender\Features" /v "TamperProtection" /t REG_DWORD /d "0" /f

rem https://technet.microsoft.com/en-us/itpro/powershell/windows/defender/set-mppreference
rem https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0290

rem Exclusion in WD can be easily set with an elevated cmd, so that makes it super easy to damage any pc.
rem WMIC /NAMESPACE:\\root\Microsoft\Windows\Defender PATH MSFT_MpPreference call Add ExclusionPath="xxxxxx

rem To disable System Guard Runtime Monitor Broker
reg add "HKLM\System\CurrentControlSet\Services\SgrmBroker" /v "Start" /t REG_DWORD /d "4" /f

rem To disable Windows Defender Security Center include this
reg add "HKLM\System\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f

rem 1 - Disable Real-time protection
reg delete "HKLM\Software\Policies\Microsoft\Windows Defender" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /v "MpEnablePus" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "DisableBlockAtFirstSeen" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SpynetReporting" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SubmitSamplesConsent" /t REG_DWORD /d "2" /f

rem 0 - Disable Logging
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /v "Start" /t REG_DWORD /d "0" /f

rem Disable WD Tasks
schtasks /Change /TN "Microsoft\Windows\ExploitGuard\ExploitGuard MDM policy Refresh" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable

rem Disable WD systray icon
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "SecurityHealth" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f

rem Remove WD context menu
reg delete "HKCR\*\shellex\ContextMenuHandlers\EPP" /f
reg delete "HKCR\Directory\shellex\ContextMenuHandlers\EPP" /f
reg delete "HKCR\Drive\shellex\ContextMenuHandlers\EPP" /f

rem Disable WD services
rem reg add "HKLM\System\CurrentControlSet\Services\WdBoot" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\WdFilter" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\WdNisDrv" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d "4" /f

rem Run twice to disable WD services !!!!!

schtasks /end /tn "\Microsoft\Office\OfficeTelemetryAgentFallBack2016"
schtasks /change /tn "\Microsoft\Office\OfficeTelemetryAgentFallBack2016" /disable
schtasks /end /tn "\Microsoft\Office\OfficeTelemetryAgentLogOn2016"
schtasks /change /tn "\Microsoft\Office\OfficeTelemetryAgentLogOn2016" /disable

schtasks /end /tn "\Microsoft\Office\OfficeTelemetryAgentFallBack"
schtasks /change /tn "\Microsoft\Office\OfficeTelemetryAgentFallBack" /disable
schtasks /end /tn "\Microsoft\Office\OfficeTelemetryAgentLogOn"
schtasks /change /tn "\Microsoft\Office\OfficeTelemetryAgentLogOn" /disable

reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Outlook\Options\Mail" /v "EnableLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\Mail" /v "EnableLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Outlook\Options\Calendar" /v "EnableCalendarLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\Calendar" /v "EnableCalendarLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Word\Options" /v "EnableLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Word\Options" /v "EnableLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Office\15.0\OSM" /v "EnableLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\OSM" /v "EnableLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Office\15.0\OSM" /v "EnableUpload" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\OSM" /v "EnableUpload" /t REG_DWORD /d 0 /f

reg add "HKCU\SOFTWARE\Microsoft\Office\Common\ClientTelemetry" /v "DisableTelemetry" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry" /v "DisableTelemetry" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\Common\ClientTelemetry" /v "VerboseLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry" /v "VerboseLogging" /t REG_DWORD /d 0 /f

reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Common" /v "QMEnable" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Common" /v "QMEnable" /t REG_DWORD /d 0 /f

reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Common\Feedback" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\Feedback" /v "Enabled" /t REG_DWORD /d 0 /f

schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator"
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /disable
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\BthSQM"
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /disable
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask"
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /disable
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /disable
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\Uploader"
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\Uploader" /disable
schtasks /end /tn "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
schtasks /change /tn "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /disable
schtasks /end /tn "\Microsoft\Windows\Application Experience\ProgramDataUpdater"
schtasks /change /tn "\Microsoft\Windows\Application Experience\ProgramDataUpdater" /disable
schtasks /end /tn "\Microsoft\Windows\Application Experience\StartupAppTask"
schtasks /change /tn "\Microsoft\Windows\Application Experience\StartupAppTask" /disable"
schtasks /end /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
schtasks /change /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /disable
schtasks /end /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver"
schtasks /change /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" /disable
schtasks /end /tn "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem"
schtasks /change /tn "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /disable
schtasks /end /tn "\Microsoft\Windows\Shell\FamilySafetyMonitor"
schtasks /change /tn "\Microsoft\Windows\Shell\FamilySafetyMonitor" /disable
schtasks /end /tn "\Microsoft\Windows\Shell\FamilySafetyRefresh"
schtasks /change /tn "\Microsoft\Windows\Shell\FamilySafetyRefresh" /disable
schtasks /end /tn "\Microsoft\Windows\Shell\FamilySafetyUpload"
schtasks /change /tn "\Microsoft\Windows\Shell\FamilySafetyUpload" /disable
schtasks /end /tn "\Microsoft\Windows\Autochk\Proxy"
schtasks /change /tn "\Microsoft\Windows\Autochk\Proxy" /disable
schtasks /end /tn "\Microsoft\Windows\Maintenance\WinSAT"
schtasks /change /tn "\Microsoft\Windows\Maintenance\WinSAT" /disable
schtasks /end /tn "\Microsoft\Windows\Application Experience\AitAgent"
schtasks /change /tn "\Microsoft\Windows\Application Experience\AitAgent" /disable
schtasks /end /tn "\Microsoft\Windows\Windows Error Reporting\QueueReporting"
schtasks /change /tn "\Microsoft\Windows\Windows Error Reporting\QueueReporting" /disable
schtasks /end /tn "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask"
schtasks /change /tn "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /disable
schtasks /end /tn "\Microsoft\Windows\DiskFootprint\Diagnostics"
schtasks /change /tn "\Microsoft\Windows\DiskFootprint\Diagnostics" /disable
schtasks /end /tn "\Microsoft\Windows\FileHistory\File History (maintenance mode)"
schtasks /change /tn "\Microsoft\Windows\FileHistory\File History (maintenance mode)" /disable
schtasks /end /tn "\Microsoft\Windows\PI\Sqm-Tasks"
schtasks /change /tn "\Microsoft\Windows\PI\Sqm-Tasks" /disable
schtasks /end /tn "\Microsoft\Windows\NetTrace\GatherNetworkInfo"
schtasks /change /tn "\Microsoft\Windows\NetTrace\GatherNetworkInfo" /disable
schtasks /end /tn "\Microsoft\Windows\AppID\SmartScreenSpecific"
schtasks /change /tn "\Microsoft\Windows\AppID\SmartScreenSpecific" /disable
schtasks /Change /TN "\Microsoft\Windows\WindowsUpdate\Automatic App Update" /Disable
schtasks /Change /TN "\Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" /Disable
schtasks /Change /TN "\Microsoft\Windows\Time Synchronization\SynchronizeTime" /Disable
schtasks /end /tn "\Microsoft\Windows\HelloFace\FODCleanupTask"
schtasks /change /tn "\Microsoft\Windows\HelloFace\FODCleanupTask" /disable
schtasks /end /tn "\Microsoft\Windows\Feedback\Siuf\DmClient"
schtasks /change /tn "\Microsoft\Windows\Feedback\Siuf\DmClient" /disable
schtasks /end /tn "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload"
schtasks /change /tn "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /disable
schtasks /end /tn "\Microsoft\Windows\Application Experience\PcaPatchDbTask"
schtasks /change /tn "\Microsoft\Windows\Application Experience\PcaPatchDbTask" /disable
schtasks /end /tn "\Microsoft\Windows\Device Information\Device"
schtasks /change /tn "\Microsoft\Windows\Device Information\Device" /disable
schtasks /end /tn "\Microsoft\Windows\Device Information\Device User"
schtasks /change /tn "\Microsoft\Windows\Device Information\Device User" /disable

schtasks /end /tn "\Microsoft\XblGameSave\XblGameSaveTask"
schtasks /change /tn "\Microsoft\XblGameSave\XblGameSaveTask" /disable
schtasks /end /tn "\Microsoft\XblGameSave\XblGameSaveTaskLogon"
schtasks /change /tn "\Microsoft\XblGameSave\XblGameSaveTaskLogon" /disable


echo|(set /p="Windows Registry Editor Version 5.00" & echo.) >> reged.reg
echo|(set /p="" & echo.) >> reged.reg
echo|(set /p="[HKEY_CURRENT_USER\Software\Policies\microsoft\office\16.0\osm\preventedapplications]" & echo.) >> reged.reg
echo|(set /p=""accesssolution"=dword:00000001" & echo.) >> reged.reg
echo|(set /p=""olksolution"=dword:00000001" & echo.) >> reged.reg
echo|(set /p=""onenotesolution"=dword:00000001" & echo.) >> reged.reg
echo|(set /p=""pptsolution"=dword:00000001" & echo.) >> reged.reg
echo|(set /p=""projectsolution"=dword:00000001" & echo.) >> reged.reg
echo|(set /p=""publishersolution"=dword:00000001" & echo.) >> reged.reg
echo|(set /p=""visiosolution"=dword:00000001" & echo.) >> reged.reg
echo|(set /p=""wdsolution"=dword:00000001" & echo.) >> reged.reg
echo|(set /p=""xlsolution"=dword:00000001" & echo.) >> reged.reg
echo|(set /p="" & echo.) >> reged.reg
echo|(set /p="[HKEY_CURRENT_USER\Software\Policies\microsoft\office\16.0\osm\preventedsolutiontypes]" & echo.) >> reged.reg
echo|(set /p=""agave"=dword:00000001" & echo.) >> reged.reg
echo|(set /p=""appaddins"=dword:00000001" & echo.) >> reged.reg
echo|(set /p=""comaddins"=dword:00000001" & echo.) >> reged.reg
echo|(set /p=""documentfiles"=dword:00000001" & echo.) >> reged.reg
echo|(set /p=""templatefiles"=dword:00000001" & echo.) >> reged.reg
echo|(set /p="" & echo.) >> reged.reg
start reged.reg
cls
echo|(set /p="Click yes" & echo.)
pause
del reged.reg
cls
echo|(set /p="Open Asar Installing (https://openasar.dev/)" & echo.)

C:\Windows\System32\TASKKILL.exe /f /im DiscordPtb.exe
C:\Windows\System32\TASKKILL.exe /f /im DiscordPtb.exe
C:\Windows\System32\TASKKILL.exe /f /im DiscordPtb.exe

C:\Windows\System32\TIMEOUT.exe /t 5 /nobreak

copy /y "%localappdata%\DiscordPTB\app-1.0.1017\resources\app.asar" "%localappdata%\DiscordPTB\app-1.0.1017\resources\app.asar.backup"

powershell -Command "Invoke-WebRequest https://github.com/GooseMod/OpenAsar/releases/download/nightly/app.asar -OutFile \"$Env:LOCALAPPDATA\DiscordPTB\app-1.0.1017\resources\app.asar\""

start "" "%localappdata%\DiscordPtb\Update.exe" --processStart DiscordPtb.exe

goto 2>nul & del "%~f0"

C:\Windows\System32\TASKKILL.exe /f /im Discord.exe
C:\Windows\System32\TASKKILL.exe /f /im Discord.exe
C:\Windows\System32\TASKKILL.exe /f /im Discord.exe

C:\Windows\System32\TIMEOUT.exe /t 5 /nobreak

copy /y "%localappdata%\Discord\app-1.0.9005\resources\app.asar" "%localappdata%\Discord\app-1.0.9005\resources\app.asar.backup"

powershell -Command "Invoke-WebRequest https://github.com/GooseMod/OpenAsar/releases/download/nightly/app.asar -OutFile \"$Env:LOCALAPPDATA\Discord\app-1.0.9005\resources\app.asar\""

start "" "%localappdata%\Discord\Update.exe" --processStart Discord.exe

goto 2>nul & del "%~f0"

C:\Windows\System32\TASKKILL.exe /f /im DiscordCanary.exe
C:\Windows\System32\TASKKILL.exe /f /im DiscordCanary.exe
C:\Windows\System32\TASKKILL.exe /f /im DiscordCanary.exe

C:\Windows\System32\TIMEOUT.exe /t 5 /nobreak

copy /y "%localappdata%\DiscordCanary\app-1.0.48\resources\app.asar" "%localappdata%\DiscordCanary\app-1.0.48\resources\app.asar.backup"

powershell -Command "Invoke-WebRequest https://github.com/GooseMod/OpenAsar/releases/download/nightly/app.asar -OutFile \"$Env:LOCALAPPDATA\DiscordCanary\app-1.0.48\resources\app.asar\""

start "" "%localappdata%\DiscordCanary\Update.exe" --processStart DiscordCanary.exe

goto 2>nul & del "%~f0"














cls
echo|(set /p="Tron Installing" & echo.)
powershell -Command "Invoke-WebRequest https://tinyurl.com/tronscriptforhardening -OutFile C:\Users\%USERNAME%\Documents\tron.exe"
start C:\Users\%USERNAME%\Documents\tron.exe
pause
del C:\Users\%USERNAME%\Documents\tron.exe
start C:\Users\%USERNAME%\Documents\tron\tron.bat
cls
echo|(set /p="Proceed with tron instructions!" & echo.)
pause
cls
echo|(set /p="Make sure you turned tron off!!" & echo.)
pause
del C:\Users\%USERNAME%\Documents\tron\
cls
echo|(set /p="Cleanup" & echo.)
del %temp%

cls
echo|(set /p="THANKS FOR USING MY HARDENING SCRIPT" & echo.)







