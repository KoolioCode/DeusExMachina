@echo off

color 0A

REM Threat Actors Windows Server

echo                             341                                      
echo                               6082                                   
echo                                40003                                 
echo                                 00007                                
echo                                400003                                
echo                               60000877                               
echo                             20000087 7983                            
echo                           20000004     005                           
echo                         60000006      4009                           
echo                       600000087      60001                           
echo                      90000004      200002                            
echo                     78000006     2000003                             
echo                      4000007    6000087                              
echo           734800000006100003   60000050000000009627                  
echo    74900095317          16001  500004         711268000843           
echo   00067                    7447 30003                 400002         
echo  30004                            7607                200004         
echo   0000009421                          1         135600000005         
echo   000000000000000000896455233333222244690000000000000000000217       
echo   9000215900000000000000000000000000000000000000000000000000000083   
echo   40005    78000000000000000000000000000000000000000000000849000009  
echo   30009     90000000000000000000000000000000000000000000002   300004 
echo    80087    4000000000000000000000000000000000000000000000     20009 
echo    30002    1000000000000000000000000000000000000000000005     40005 
echo     6000     00000000000000000000000000000000000000000000     20009  
echo     10008    50000000000000000000000000000000000000000002  7500005   
echo      50009   700000000000000000000000000000000000000000080000009     
echo       4000067 500000000000000000000000000000000000000000000061       
echo        600000000000000000000000000000000000000000000087              
echo       28000000000000000000000000000000000000000000000041             
echo   190000000000000000000000000000000000000000000000000000005          
echo 7800000000000000000000000000000000000000000000000000000000004        
echo 60000000000340000000000000000000000000000000000046000000000001       
echo 2000000000083 734800000000000000000000000008437 40000000000097       
echo   600000000000937     73254669996645237     1400000000000082         
echo     740000000000000008642317 7  7712549800000000000000083            
echo          35680000000000000000000000000000000000009421                
echo                   12498880000000000008896521  

echo HAVE 
echo YOU 
echo DONE 
echo FORENSICS!!! 
echo Do not run until forensics are done.
echo Do not run until on MPS Systems.


pause


cd..


@echo on

REM Chocolatey install

@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "[System.Net.ServicePointManager]::SecurityProtocol = 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))" && SET "PATH=%PATH%;%ALLUSERSPROFILE%\chocolatey\bin"


REM Admin and guest disable

net user administrator /active:no
net user guest /active:no


REM Firewall

netsh advfirewall set allprofiles state on


REM User Txt Doc Creation

cd Documents 
    copy NUL Users.txt
    notepad Users.txt
cd..


REM Telnet

DISM /online /disable-feature /featurename:TelnetClient
DISM /online /disable-feature /featurename:TelnetServer

sc stop "TlntSvr"
sc config "TlntSvr" start= disabled


REM Registry

sc stop "TermService"
    sc config "TermService" start= disabled
sc stop "SessionEnv"
    sc config "SessionEnv" start= disabled
sc stop "UmRdpService"
    sc config "UmRdpService" start= disabled
sc stop "RemoteRegistry"
    sc config "RemoteRegistry" start= disabled


REM Remote Disable

reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f 
netsh advfirewall firewall set rule group="remote desktop" new enable=No 


REM Fix Those Policies

Function Parse-SecPol($CfgFile){ 
    secedit /export /cfg "$CfgFile" | out-null
    $obj = New-Object psobject
    $index = 0
    $contents = Get-Content $CfgFile -raw
    [regex]::Matches($contents,"(?<=\[)(.*)(?=\])") | %{
        $title = $_
        [regex]::Matches($contents,"(?<=\]).*?((?=\[)|(\Z))", [System.Text.RegularExpressions.RegexOptions]::Singleline)[$index] | %{
            $section = new-object psobject
            $_.value -split "\r\n" | ?{$_.length -gt 0} | %{
                $value = [regex]::Match($_,"(?<=\=).*").value
                $name = [regex]::Match($_,".*(?=\=)").value
                $section | add-member -MemberType NoteProperty -Name $name.tostring().trim() -Value $value.tostring().trim() -ErrorAction SilentlyContinue | out-null
            }
            $obj | Add-Member -MemberType NoteProperty -Name $title -Value $section
        }
        $index += 1
    }
    return $obj
}

Function Set-SecPol($Object, $CfgFile){
   $SecPool.psobject.Properties.GetEnumerator() | %{
        "[$($_.Name)]"
        $_.Value | %{
            $_.psobject.Properties.GetEnumerator() | %{
                "$($_.Name)=$($_.Value)"
            }
        }
    } | out-file $CfgFile -ErrorAction Stop
    secedit /configure /db c:\windows\security\local.sdb /cfg "$CfgFile" /areas SECURITYPOLICY
}


$SecPool = Parse-SecPol -CfgFile C:\test\Test.cgf
$SecPool.'System Access'.EnforcePasswordHistory = 3
$SecPool.'System Access'.PasswordComplexity = 1
$SecPool.'System Access'.MinimumPasswordLength = 8
$SecPool.'System Access'.MaximumPasswordAge = 60
$SecPool.'System Access'.MinimumPasswordAge = 60

Set-SecPol -Object $SecPool -CfgFile C:\Test\Test.cfg


REM Chocolatey Manage Programs

choco uninstall flashplayerplugin -y
choco uninstall wireshark -y
choco install firefox -y
choco install googlechrome -y
choco install inkscape -y
choco install malwarebytes -y 
choco install kb3035131 -y
choco install kb3063858 -y


REM Windows Scan

cd C:\ProgramData\Microsoft\Windows Defender\Platform\4*
mpcmdrun -scan -scantype 2

