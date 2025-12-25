/*
    木马检测规则
    专门用于检测各种类型的木马程序
*/

rule Remote_Access_Trojan
{
    meta:
        description = "检测远程访问木马(RAT)"
        author = "Virus Sandbox System"
        date = "2024-01-01"
        severity = "high"
        category = "trojan"

    strings:
        $rat1 = "RemoteDesktop" ascii wide
        $rat2 = "ScreenCapture" ascii wide
        $rat3 = "KeyLogger" ascii wide
        $rat4 = "FileManager" ascii wide
        $rat5 = "ProcessManager" ascii wide
        $rat6 = "RegistryEditor" ascii wide
        $rat7 = "CommandShell" ascii wide
        $rat8 = "WebcamCapture" ascii wide

    condition:
        3 of ($rat*)
}

rule Banking_Trojan
{
    meta:
        description = "检测银行木马"
        author = "Virus Sandbox System"
        date = "2024-01-01"
        severity = "high"
        category = "trojan"

    strings:
        $bank1 = "webinject" ascii wide nocase
        $bank2 = "formgrabber" ascii wide nocase
        $bank3 = "certificate" ascii wide
        $bank4 = "banking" ascii wide nocase
        $bank5 = "creditcard" ascii wide nocase
        $bank6 = "paypal" ascii wide nocase
        $bank7 = "login" ascii wide
        $bank8 = "password" ascii wide
        $bank9 = "account" ascii wide

    condition:
        3 of ($bank*)
}

rule Backdoor_Indicators
{
    meta:
        description = "检测后门程序"
        author = "Virus Sandbox System"
        date = "2024-01-01"
        severity = "high"
        category = "backdoor"

    strings:
        $back1 = "bind_shell" ascii wide
        $back2 = "reverse_shell" ascii wide
        $back3 = "backdoor" ascii wide nocase
        $back4 = "remote_shell" ascii wide
        $back5 = "cmd_exec" ascii wide
        $back6 = "shell_exec" ascii wide
        $back7 = "system(" ascii wide
        $back8 = "exec(" ascii wide

    condition:
        2 of ($back*)
}

rule Downloader_Trojan
{
    meta:
        description = "检测下载器木马"
        author = "Virus Sandbox System"
        date = "2024-01-01"
        severity = "medium"
        category = "trojan"

    strings:
        $down1 = "URLDownloadToFile" ascii wide
        $down2 = "InternetReadFile" ascii wide
        $down3 = "HttpQueryInfo" ascii wide
        $down4 = "WinHttpReceiveResponse" ascii wide
        $down5 = "download" ascii wide nocase
        $down6 = "payload" ascii wide nocase
        $down7 = "dropper" ascii wide nocase
        $down8 = "stage2" ascii wide nocase

    condition:
        2 of ($down*)
}

rule Spyware_Indicators
{
    meta:
        description = "检测间谍软件"
        author = "Virus Sandbox System"
        date = "2024-01-01"
        severity = "medium"
        category = "spyware"

    strings:
        $spy1 = "GetWindowText" ascii wide
        $spy2 = "GetForegroundWindow" ascii wide
        $spy3 = "FindWindow" ascii wide
        $spy4 = "EnumWindows" ascii wide
        $spy5 = "GetClipboardData" ascii wide
        $spy6 = "SetClipboardData" ascii wide
        $spy7 = "screenshot" ascii wide nocase
        $spy8 = "monitor" ascii wide nocase

    condition:
        3 of ($spy*)
}

rule Rootkit_Techniques
{
    meta:
        description = "检测Rootkit技术"
        author = "Virus Sandbox System"
        date = "2024-01-01"
        severity = "high"
        category = "rootkit"

    strings:
        $root1 = "NtQuerySystemInformation" ascii wide
        $root2 = "ZwQuerySystemInformation" ascii wide
        $root3 = "NtQueryDirectoryFile" ascii wide
        $root4 = "ZwQueryDirectoryFile" ascii wide
        $root5 = "DeviceIoControl" ascii wide
        $root6 = "CreateService" ascii wide
        $root7 = "OpenSCManager" ascii wide
        $root8 = "driver" ascii wide nocase

    condition:
        2 of ($root*)
}

rule Stealer_Malware
{
    meta:
        description = "检测信息窃取恶意软件"
        author = "Virus Sandbox System"
        date = "2024-01-01"
        severity = "high"
        category = "stealer"

    strings:
        $steal1 = "CryptUnprotectData" ascii wide
        $steal2 = "sqlite3" ascii wide
        $steal3 = "Login Data" ascii wide
        $steal4 = "Web Data" ascii wide
        $steal5 = "Cookies" ascii wide
        $steal6 = "History" ascii wide
        $steal7 = "Bookmarks" ascii wide
        $steal8 = "Preferences" ascii wide
        $steal9 = "wallet.dat" ascii wide
        $steal10 = "keystore" ascii wide

    condition:
        3 of ($steal*)
}

rule Botnet_Communication
{
    meta:
        description = "检测僵尸网络通信"
        author = "Virus Sandbox System"
        date = "2024-01-01"
        severity = "high"
        category = "botnet"

    strings:
        $bot1 = "C&C" ascii wide nocase
        $bot2 = "command_control" ascii wide nocase
        $bot3 = "botnet" ascii wide nocase
        $bot4 = "zombie" ascii wide nocase
        $bot5 = "IRC" ascii wide
        $bot6 = "HTTP POST" ascii wide
        $bot7 = "base64" ascii wide
        $bot8 = "encrypt" ascii wide

    condition:
        2 of ($bot*)
}

rule Adware_Indicators
{
    meta:
        description = "检测广告软件"
        author = "Virus Sandbox System"
        date = "2024-01-01"
        severity = "low"
        category = "adware"

    strings:
        $ad1 = "advertisement" ascii wide nocase
        $ad2 = "popup" ascii wide nocase
        $ad3 = "banner" ascii wide nocase
        $ad4 = "affiliate" ascii wide nocase
        $ad5 = "tracking" ascii wide nocase
        $ad6 = "analytics" ascii wide nocase
        $ad7 = "monetize" ascii wide nocase
        $ad8 = "revenue" ascii wide nocase

    condition:
        2 of ($ad*)
}

rule Worm_Propagation
{
    meta:
        description = "检测蠕虫传播机制"
        author = "Virus Sandbox System"
        date = "2024-01-01"
        severity = "high"
        category = "worm"

    strings:
        $worm1 = "NetShareEnum" ascii wide
        $worm2 = "NetUserEnum" ascii wide
        $worm3 = "WNetEnumResource" ascii wide
        $worm4 = "FindFirstFile" ascii wide
        $worm5 = "FindNextFile" ascii wide
        $worm6 = "CopyFile" ascii wide
        $worm7 = "autorun.inf" ascii wide nocase
        $worm8 = "USB" ascii wide nocase

    condition:
        3 of ($worm*)
}