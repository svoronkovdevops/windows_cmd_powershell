# Becoming a Power User Windows commands

## Content


[Help](#help)

[Directories](#directories)

[History](#history)

[Files](#files)

[Searching in files](#searching-in-files)

[IO](#io)

[Users](#users)

[ACL](#acl)

[Packages](#packages)

[Link](#link)

[Filesystem](#filesystem)

[Filesystem repair](#filesystem-repair)

[Processes](#processes)

[SSH](#ssh)

[RDP](#rdp)

[Debug](#debug)

[Path](#path)

[Variables](#variables)

[Format commands](#format-commands)

[Netwirking](#networking)

[Packet management]()

[Power management](#power-management)

[Content](#content)

[Contents](README.md#contents)



[youtube playlist](https://www.youtube.com/watch?v=ztevwVltDPs&list=PLWbKFGwwAIAdkHHOtJe2zMWloBTlTIzXV)


`cls` - clean screen

## Help

`$PSVersionTable.PSVersion` ** show powershell version

`ls C:\`  ***show directories and files on c:

`ls -Force C:\`  ***show directories and fikes on c: including hidden or system

`Get-Help ls`  ***help about comand ls

`Get-Help ls -Full`  ***help about comand ls

[Content](#content)

## Directories

`pwd` ** print working directory

`cd C:\Users\vsvdev` **navigate to C:\Users\vsvdev

`cd .. `  **one directory higter

`cd ~\Desktop `  ****navigate to user desktop

`Tab` autocomplition tap one symbol then use Tab button

`mkdir my_directory` ** create directory

`mkdir 'my directory'`

`mkdir my`directory `new`

[Content](#content)

## History

`history` **history of comands then choose the number

`Get-History | Where-Object {$_.CommandLine -like "*Service*"}`

`Get-History | Select-Object -Property `*

`Invoke-History -Id 2`

` ctrl-R`  to search

[Content](#content)


## Files

`cp myfile.txt C:\Users\vsvdev\Desktop` **copy myfile.txt to desktop

`cp *.txt C:\Users\vsvdev\Desktop` **copy all files type .txt to desktop

`cp files C:\Users\vsvdev\Desktop` **directory files to desktop

`cp files C:\Users\vsvdev\Desktop -Recurse -Verbose` **directory and subderictories files to desktop



`mv my_doc.txt your_doc.txt` **rename doc

`mv your_doc.txt C:\Users\vsvdev\Desktop` ** move doc to desktop

`mv *_doc.txt C:\Users\vsvdev\Desktop`




`rm doc.txt` 

`rm important_syst_file -Force`

`rm my_folder -Recurse`



`cat import.txt` open file import.txt

`more import.txt` **fill page 

`enter`**next line

`space` **next page

`q` **exit

`cat import.txt -Head 10` ***show first 10

`cat import.txt -Tail 10` ***show last 10



`start notepad++ hi.txt` ** open hi.txt in notepad++ 

`Get-Alias ls` ** show how it executes

`Get-ChildItem C:\`

`cmd.exe dir`

`dir/?` **help by dir

[Content](#content)

## Searching in files

!!!! turn on inddexing which allow to better searc hand search in files 
run->indexing Options-> users->Advanced->
File Types->radioButton Index Properties and File Contents->ok->ok->close

`Notepad++ ->ctrl+shift+F ` open Find in files and choose directory

Select-String cow my.txt

Select-String cow *.txt

directories 

`ls 'C:\Program Files\' -Recurse -Filter *.exe`

[Content](#content)


## IO

`echo www > int.txt `** send www to int.txt

`echo www >> int.txt `** append www in int.txt

``>&1``	Redirects the specified stream to the Success stream

`cat words.txt | Select-String st  `**show strings with st

`cat words.txt | Select-String st > st_words.txt `**record strings with st to file st_words.txt
stdin
stdout
stderr

`rm secure_file 2> errors.txt`

`rm secure_file 2> $null `** run stream in black hole(in nothing)

`for pS 7 Get-Help about_redirection`

[Content](#content)


## Users

Windows domain - a network of computers, users, files, 
etc that are added to a central database.

in search write `computer` and press enter select `Local Users and Groups`

`Get-LocalUser`  -show info about users

`Get-LocalGroup` -show groups

`Get-LocalGroupMember Administrators `-show group (administrators) members

`net user username 'some_pass'` -set password

`net user username *  `-to hide password

`net user username /logonpasswordchg:yes `-user have to change his passw when log in

`net user username * /add `-create user username 

then

`net user username /logonpasswordchg:yes`

`net user username password /add /logonpasswordchg:yes`

`net user username /del`  -delete user username

`Remove-LocalUser username `-delete user username

`New-LocalGroup -Name "Security" `-create localgroup

`net user username `-show info about user username

`Get-LocalGroupMember -Group "Administrators" `-List the members of group

`Add-LocalGroupMember -Group Security `-Member username -Verbose -add user to group

`Remove-LocalGroupMember -Group Security `-Member username -remove user from group

`Remove-LocalGroup -Name Security `-remove group

[Content](#content)

## ACL

In Windows, files and directory permissions are assignet using
Acess Control List or ACLs. Specifically,we're gonna work with
 Dictionary Access Control Lists or DACLs.

Windows files and folders can also have
Ststem Access Control Lists or SACLs assignet to them.

`on directory right click and select properties then security`

`icacls C:\Users\vsvdev\Desktop `-show ussers who has an access 

to directory and permissions

`Get-ACL -Path "~/Desktop" `-show ussers who has an access 

`(Get-ACL -Path "~/Desktop").Access | Format-Table IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags -AutoSize`

`icacls /?  `-help

output`C:\Users\vsvdev\Desktop NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
                        BUILTIN\Administrators:(I)(OI)(CI)(F)
                        DESKTOP-LEGANF1\vsvdev:(I)(OI)(CI)(F)`
(I)(OI)(CI)(F)

    N - no access
                F - full access
                M - modify access
                RX - read and execute access
                R - read-only access
                W - write-only access
                D - delete access
        a comma-separated list in parentheses of specific rights:
                DE - delete
                RC - read control
                WDAC - write DAC
                WO - write owner
                S - synchronize
                AS - access system security
                MA - maximum allowed
                GR - generic read
                GW - generic write
                GE - generic execute
                GA - generic all
                RD - read data/list directory
                WD - write data/add file
                AD - append data/add subdirectory
                REA - read extended attributes
                WEA - write extended attributes
                X - execute/traverse
                DC - delete child
                RA - read attributes
                WA - write attributes
        ** when create inside new folder it can inherit oermissions.
inheritance rights may precede either form and are applied
        only to directories:
                (OI) - object inherit
                (CI) - container inherit
                (IO) - inherit only
                (NP) - don't propagate inherit
                (I) - permission inherited from parent container

***********************
***Modify permissions**
***********************

`icacls 'C:\Vacation Pictures\' /grant 'Everyone:(OI)(CI)(R)' `-grant to group

`icacls 'C:\Vacation Pictures\' /grant 'Authenticated Users:(OI)(CI)(R)'`

`icacls 'C:\Vacation Pictures\' /remove Everyone `-remove permission

`icacls 'C:\Users\vsvdev\Desktop' /grant "username:(OI)(CI)(RX)" `-give user access

`icacls C:\Users\vsvdev\Desktop /grant "username:(OI)(CI)(RX)"`

`icacls 'C:\Users\vsvdev\Desktop' /remove username `-close for user

`cmd  icacls "C:\Vacation Pictures\" /grant Everyone:(OI)(CI)(R)`



************************
Special permissons******
************************

when look in GUI to permission `chose adwanced` and you'll see smth like 'Create files / write data'

`icacls C:\Windows\Temp`


[Content](#content)



## Packages

7zip install for windows
https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.archive/compress-archive?view=powershell-7.3

`Compress-Archive -Path C:\Users\username\Desktop\test ~\Desktop\testArchive.zip`

`Find-Package sysinternals -IncludeDependencies`

`Register-PackageSource -Name chocolatey -ProviderName Chocolatey -Location http://chocolatey.org/api/v2`

`Get-Packagesource`

`Find-Package sysinternals -IncludeDependencies`

`Install-Package -Name sysinternals`

`Get-Package -name sysinternals`

`Uninstall-Package -Name sysinternals`

`orca.exe ` **** tool microsoft help you to create packages

drivers in search type `devmgmt.msc`

[Content](#content)



## Link

`create file 1.txt`

`create shortcut for 1.txt = 1_shortcut.lnk `-rigth click on file

`notepad.exe 1_shortcut.lnk `-open shortcut using notepad

`mklink 1_symlink 1.txt `-create symbolic link to file 1.txt

`notepad.exe 1_symlink `-open symbolic link using notepad

`mklink /H 1_hardlink 1.txt `-create hard link to file 1.txt(points out to the record file number if we change name it won't affect)


[Content](#content)




## Filesystem

filesystem ntfs

we can't read usb flash with ext4 filesystem
fat32 can be read in Windows linux macOs but 32Gb max filesystem 4 Gb maxfile

MBR

master boot record 2Tb max volume size, primary partitions
we can have only 4 primary partitions if we need more
Partition1 ...4
-extended
 -logical


GPT used by BIOS UEFI
GUID partition table
2Tb or greater volume size
one type of partition
unlimited partitions

format disc ffrom cmd


Diskpart

`diskpart` - run the programm

`list disk` -show disks

`select disk disk_number `-select disk by number

`clean` -remove any and all partition or volume formatting from selected disk

`create partition primary` -create partition on selected disk

`select partition 1 `-select partition on selected disk

`active `-mark partition as active

`format FS=NTFS label=my_drive quick `-format to filesystem NTFS quick format

`virtual memory swap ->system->advanced ->performance->advanced`



[Content](#content)


## Filesystem repair


cmd
fsutil repair query C: -repair C:

`chkdsk /F D: -repair /F`  (fix problem if find)

`assoc` -show files and associated programm

`assoc .mp4=VLC.vlc`  -associate mp4 format with vlc player

`chldsk /f` -check disk and fix errors

`chldsk /r` -check physical sector on disk and fix errors

`sfc /scannow` - scan file system and fix errors

`DISM /Online /Cleanup-Image /CheckHealth` - it will notify you if any errors are discovered. It will also indicate whether a Windows image is healthy, repairable, or unrepairable. 

`DISM /Online /Cleanup-Image /ScanHealth` -  This command is used to assist users in scanning for and locating problems in their operating systems. ScanHealth only performs an initial scan and reports on findings  no repairs are performed.

`DISM /Online /Cleanup-Image /RestoreHealth`

[Content](#content)


## Processes

Session manager subsystem `smss.exe`

Log-in process `winlogon.exe`

Client/Server runtime subsystem `csrss.exe`(GUI and comand line)

init when run smss.exe

Each process when created needs to have parent and it inherited Environment(var and settings)from parent
unlike linux windows process can be independent from parents

`powershell run`

`notepad.exe`

if we close powershell it's still working


**
Kill process by port
Run command-line as an Administrator. Then run the below mention command.

`netstat -ano | findstr : port number`

`netstat -ano | findstr : 8080` you recive

TCP 0.0.0.0:8080    LISTENING 17760

Then you execute this command after identify the PID.
`taskkill /PID typeyourPIDhere /F`

`taskkill /PID 17760/F` and enter to check `netstat -ano | findstr : 8080` 


cmd
`taskkill /pid 5856`

`taskmgr.exe` - task manager (search or ctrl+Shift+Esc)

cmd

`tasklist `-show processes

powershell

`Get-Process `-show processes

signals
sigint(signal interrupt) `ctrl+C`

we can download official `microsoft ProcessExplorer`
where we can manage and find process `ctrl+f`

powershell

`Get-Process notepad` -show info about notepad's process

resource monitor
Get-Process 
`Get-Process | Sort CPU -descending | Select -first 3 -Property ID,ProcessName,CPU`


`tasklist | findstr script`

`taskkill /f /pid 2018 `-kill process force with pid 2018


[Content](#content)

## SSH

It should be installed before
putty.exe -ssh name@ip 22

putty portable or we can use mobaxterm portable(better than putty)


[Content](#content)


## RDP
to connect windows we use RDP
Microsoft terminal services client mstsc.exe creates rdp connections
PC->right click properties->remote->
search remote desktop app(to conecct)

copy file to other machine use putty secure
pscp.exe ~\Desktop\shared.txt name@ip:


`net share ShareMe=C:\Users\user\Desktop\ShareMe /grant:everyone,full `-share folder to all in network

[Content](#content)

## Debug

Event viewer show events on pc
`eventvwr.msc` then we can create custom view with filter(critical, error, last hour)
and select event logs(wind or app or both)

`clonezilla `- open source for backup and clone


`ipconfig /flushdns `- clean dns cache

[Content](#content)




## Path

`echo %PATH%` - show path in cmd

`$Env:Path` -  show path in powershell

Path `C:\Program Files\Java\jdk1.8.0_211\bin`



[Content](#content)

## Variables

`set` - show all variables cmd

`$Env:<variable-name> = "<new-value>"`

`$Env:VALUE = 25` - set up local variable VALUE with value 25

`echo $Env:VALUE ` - show local variable VALUE

`set LifeAnswerVar=42` - set up local variable LifeAnswerVar with value 42

`echo %LifeAnswerVar%` - show variable LifeAnswerVar

`C:\> setx VAR_NAME "VALUE"` - permanently(available after restart) for current user

`setx A "A"` - cmd add variable A with value A

`setx /M VAR_NAME "VALUE"` 

`setx /M B "B"` - powershell add B with value B

`[Environment]::SetEnvironmentVariable("variable_name","variable_value","User")` - if you want to create a user environment variable powershell

`[Environment]::SetEnvironmentVariable("variable_name","variable_value","Machine")` - if you want to create a system environment variable powershell

`REG delete "HKCU\Environment" /F /V "variable_name"` - if user environment variable

`REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /F /V "variable_name"` - if system environment variable

`reg delete "HKCU\Environment" /v VAR_NAME /f`  - Delete User Environment Variable

`REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /F /V VAR_NAME` - Delete System-Wide Environment Variable

`[Environment]::SetEnvironmentVariable("variable_name", $null ,"User")` if user profile variable

`[Environment]::SetEnvironmentVariable("LifeAnswerVar", $null ,"User")` 

`[Environment]::SetEnvironmentVariable("variable_name", $null ,"Machine")` if system-wide variable

`[Environment]::SetEnvironmentVariable("A", $null ,"Machine")`




`JAVA_HOME` `C:\Program Files\Java\jdk1.8.0_211`



[Content](#content)

## Format commands


Solution 1 In CMD, Use ^ , example

```bat
docker run -dp 3000:3000 ^
  -w /app -v "$(pwd):/app" ^
  --network todo-app ^
  -e MYSQL_HOST=mysql ^
  -e MYSQL_USER=root ^
  -e MYSQL_PASSWORD=secret ^
  -e MYSQL_DB=todos ^
  node:12-alpine ^
  cmd "npm install && yarn run start"
 ```


Solution 2 In PowerShell, Use ` (backtick) , Example
```powershell
docker run -dp 3000:3000 `
  -w /app -v "$(pwd):/app" `
  --network todo-app `
  -e MYSQL_HOST=mysql `
  -e MYSQL_USER=root `
  -e MYSQL_PASSWORD=secret `
  -e MYSQL_DB=todos `
  node:12-alpine ^
  cmd "npm install && npm run start"
```

[Content](#content)


 
## Networking

`ipconfig /all`

`ipconfig /all | findstr DNS`

`ipconfig /release` delete IP 

`ipconfig /renew`    get new IP

`ipconfig /displaydns`

`ipconfig /displaydns | clip ` -copy to buffer result

`ipconfig /flushdns `- remove cache

`nslookup google.com `- where IP and dns


`getmac /v` -show mac adress

`powercfg /energy` - show config power


`netsh wlan show wlanreport `- report about wireless

`netsh interface show interface `- show interfaces

`netsh interface ip show address | findstr "IP Address"`

`netsh interface dnsservers`

`netsh advfirewall set allprofiles state off` - turn off wind defender

`netsh advfirewall set allprofiles state on`

`ping google.com`

`ping -t google.com `-endless ping
 
`tracert google.com` - show route

`tracert -d google.com` - show route

netstat 

`netstat -af`  -show opened ports

`netstat -o ` - show processes on opened ports

`netstat -e -t 5` -show statistics save and send each 5 sec

`route print` - show routes on pc

`route add ip mask 255.255.255.0 10.7.1.44` - we can specify how our pc reaches certain networks(ip) throught 10.7...
route delete IP 

#### Host

Edit host file`C:\Windows\System32\drivers\etc\hosts` -> copy to desktop -> edit -> replace existing


[Content](#content)


## Packet management

[chocolatey](https://docs.chocolatey.org/en-us/choco/setup)


run powershell as admin

Run `Get-ExecutionPolicy`. 
If it returns Restricted, then run `Set-ExecutionPolicy AllSigned` 
or `Set-ExecutionPolicy Bypass -Scope Process`.
run command:
`Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))`
If after command setup not started and all red->close powerShell.
you should turn off your antivirus for 10 minutes 
run powershell as admin and try again.

`choco install virtualbox`

`choco install vagrant`

`choco install git`

`choco install jdk8`

`choco install maven`

`choco install awscli`

`choco install intellijidea-community`

`choco install sublimetext3.app`

`Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))`

https://community.chocolatey.org/packages?q=zip
unzip

choco install git
choco install git
Install SDKMAN in a custom project folder in C drive.
 
run gitBash
export SDKMAN_DIR="/c/project/lib/sdkman" && curl -s "https://get.sdkman.io" | bash
https://walterteng.com/using-sdkman-on-windows

I had to make two changes:

Set JAVA_HOME to C:\Users\ngeor\.sdkman\candidates\java\current
Add C:\Users\ngeor\.sdkman\candidates\maven\current\bin to my PATH

`JAVA_HOME=C:\Program Files\Java\jdk-17.0.2` - normal path


[Content](#content)

## Power management


`powercfg /batteryreport` - create report

`shutdown /r /fw /f /t 0 ` -restart pc and open bios settings


[Content](#content)
