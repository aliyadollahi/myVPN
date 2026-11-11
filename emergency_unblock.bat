@echo off
:: Removes VPN Gate Guardian kill-switch firewall rules and restores internet access.
:: Right-click -> Run as administrator
title VPN Gate Guardian - Emergency Unblock
powershell -NoProfile -ExecutionPolicy Bypass -Command "Remove-NetFirewallRule -Group 'VPNGateGuardian' -ErrorAction SilentlyContinue; 'Kill-switch rules removed.'"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f >nul
echo System proxy disabled.
pause
