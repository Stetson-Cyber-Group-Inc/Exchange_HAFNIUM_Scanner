// thank you to Microsoft, Volexity and Florian Roth for the yara rules 
1.
rule webshell_aspx_simpleseesharp : Webshell Unclassified
{
    meta:
        author = “threatintel@volexity.com”
        date = “2021-03-01”
        description = “A simple ASPX Webshell that allows an attacker to write further files to disk.”
        hash = “893cd3583b49cb706b3e55ecb2ed0757b977a21f5c72e041392d1256f31166e2”
 
    strings:
        $header = “<%@ Page Language=\”C#\” %>”
        $body = “<% HttpPostedFile thisFile = Request.Files[0];thisFile.SaveAs(Path.Combine”
 
    condition:
        $header at 0 and
        $body and
        filesize < 1KB
}
 
2.
rule webshell_aspx_reGeorgTunnel : Webshell Commodity
{
    meta:
        author = “threatintel@volexity.com”
        date = “2021-03-01”
        description = “A variation on the reGeorg tunnel webshell”
        hash = “406b680edc9a1bb0e2c7c451c56904857848b5f15570401450b73b232ff38928”
        reference = “https://github.com/sensepost/reGeorg/blob/master/tunnel.aspx”
 
    strings:
        $s1 = “System.Net.Sockets”
        $s2 = “System.Text.Encoding.Default.GetString(Convert.FromBase64String(StrTr(Request.Headers.Get”
        // a bit more experimental
        $t1 = “.Split(‘|’)”
        $t2 = “Request.Headers.Get”
        $t3 = “.Substring(“
        $t4 = “new Socket(“
        $t5 = “IPAddress ip;”
 
    condition:
        all of ($s*) or
        all of ($t*)
}
 
3
rule webshell_aspx_sportsball : Webshell Unclassified
{
    meta:
        author = “threatintel@volexity.com”
        date = “2021-03-01”
        description = “The SPORTSBALL webshell allows attackers to upload files or execute commands on the system.”
        hash = “2fa06333188795110bba14a482020699a96f76fb1ceb80cbfa2df9d3008b5b0a”
 
    strings:
        $uniq1 = “HttpCookie newcook = new HttpCookie(\”fqrspt\”, HttpContext.Current.Request.Form”
        $uniq2 = “ZN2aDAB4rXsszEvCLrzgcvQ4oi5J1TuiRULlQbYwldE=”
 
        $var1 = “Result.InnerText = string.Empty;”
        $var2 = “newcook.Expires = DateTime.Now.AddDays(”
        $var3 = “System.Diagnostics.Process process = new System.Diagnostics.Process();”
        $var4 = “process.StandardInput.WriteLine(HttpContext.Current.Request.Form[\””
        $var5 = “else if (!string.IsNullOrEmpty(HttpContext.Current.Request.Form[\””
        $var6 = “<input type=\”submit\” value=\”Upload\” />”
 
    condition:
        any of ($uniq*) or
        all of ($var*)
}
rule WEBSHELL_ASP_Embedded_Mar21_1 {
   meta:
      description = "Detects ASP webshells"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2021-03-05"
      score = 85
   strings:
      $s1 = "<script runat=\"server\">" nocase
      $s2 = "new System.IO.StreamWriter(Request.Form["
      $s3 = ".Write(Request.Form["
   condition:
      filesize < 100KB and all of them
}

rule APT_WEBSHELL_HAFNIUM_SecChecker_Mar21_1 {
   meta:
      description = "Detects HAFNIUM SecChecker webshell"
      author = "Florian Roth"
      reference = "https://twitter.com/markus_neis/status/1367794681237667840"
      date = "2021-03-05"
      hash1 = "b75f163ca9b9240bf4b37ad92bc7556b40a17e27c2b8ed5c8991385fe07d17d0"
   strings:
      $x1 = "<%if(System.IO.File.Exists(\"c:\\\\program files (x86)\\\\fireeye\\\\xagt.exe" ascii
      $x2 = "\\csfalconservice.exe\")){Response.Write( \"3\");}%></head>" ascii fullword
   condition:
      uint16(0) == 0x253c and
      filesize < 1KB and
      1 of them or 2 of them
}

rule APT_HAFNIUM_Forensic_Artefacts_Mar21_1 {
   meta:
      description = "Detects forensic artefacts found in HAFNIUM intrusions"
      author = "Florian Roth"
      reference = "https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/"
      date = "2021-03-02"
   strings:
      $s1 = "lsass.exe C:\\windows\\temp\\lsass" ascii wide fullword
      $s2 = "c:\\ProgramData\\it.zip" ascii wide fullword
      $s3 = "powercat.ps1'); powercat -c" ascii wide fullword
   condition:
      1 of them
}

rule APT_WEBSHELL_HAFNIUM_Chopper_WebShell: APT Hafnium WebShell {
   meta:
      description = "Detects Chopper WebShell Injection Variant (not only Hafnium related)"
      author = "Markus Neis,Swisscom"
      date = "2021-03-05"
      reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
   strings:
      $x1 = "runat=\"server\">" nocase

      $s1 = "<script language=\"JScript\" runat=\"server\">function Page_Load(){eval(Request" nocase
      $s2 = "protected void Page_Load(object sender, EventArgs e){System.IO.StreamWriter sw = new System.IO.StreamWriter(Request.Form[\"p\"] , false, Encoding.Default);sw.Write(Request.Form[\"f\"]);"
      $s3 = "<script language=\"JScript\" runat=\"server\"> function Page_Load(){eval (Request[\"" nocase  
   condition:
      filesize < 10KB and $x1 and 1 of ($s*) 
}

rule APT_WEBSHELL_Tiny_WebShell : APT Hafnium WebShell {
   meta:
      description = "Detects WebShell Injection"
      author = "Markus Neis,Swisscom"
      hash = "099c8625c58b315b6c11f5baeb859f4c"
      date = "2021-03-05"
      reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
   strings:
      $x1 = "<%@ Page Language=\"Jscript\" Debug=true%>"

      $s1 = "=Request.Form(\""
      $s2 = "eval("
   condition:
      filesize < 300 and all of ($s*) and $x1
} 

rule HKTL_PS1_PowerCat_Mar21 {
   meta:
      description = "Detects PowerCat hacktool"
      author = "Florian Roth"
      reference = "https://github.com/besimorhino/powercat"
      date = "2021-03-02"
      hash1 = "c55672b5d2963969abe045fe75db52069d0300691d4f1f5923afeadf5353b9d2"
   strings:
      $x1 = "powercat -l -p 8000 -r dns:10.1.1.1:53:c2.example.com" ascii fullword
      $x2 = "try{[byte[]]$ReturnedData = $Encoding.GetBytes((IEX $CommandToExecute 2>&1 | Out-String))}" ascii fullword

      $s1 = "Returning Encoded Payload..." ascii
      $s2 = "$CommandToExecute =" ascii fullword
      $s3 = "[alias(\"Execute\")][string]$e=\"\"," ascii
   condition:
      uint16(0) == 0x7566 and
      filesize < 200KB and
      1 of ($x*) or 3 of them
}

rule HKTL_Nishang_PS1_Invoke_PowerShellTcpOneLine {
   meta:
      description = "Detects PowerShell Oneliner in Nishang's repository"
      author = "Florian Roth"
      reference = "https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcpOneLine.ps1"
      date = "2021-03-03"
      hash1 = "2f4c948974da341412ab742e14d8cdd33c1efa22b90135fcfae891f08494ac32"
   strings:
      $s1 = "=([text.encoding]::ASCII).GetBytes((iex $" ascii wide
      $s2 = ".GetStream();[byte[]]$" ascii wide
      $s3 = "New-Object Net.Sockets.TCPClient('" ascii wide
   condition:
      all of them
}

rule WEBSHELL_ASPX_SimpleSeeSharp : Webshell Unclassified {
   meta:
      author = "threatintel@volexity.com"
      date = "2021-03-01"
      description = "A simple ASPX Webshell that allows an attacker to write further files to disk."
      hash = "893cd3583b49cb706b3e55ecb2ed0757b977a21f5c72e041392d1256f31166e2"
      reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
   strings:
      $header = "<%@ Page Language=\"C#\" %>"
      $body = "<% HttpPostedFile thisFile = Request.Files[0];thisFile.SaveAs(Path.Combine"
   condition:
      $header at 0 and
      $body and
      filesize < 1KB
}

rule WEBSHELL_ASPX_reGeorgTunnel : Webshell Commodity {
   meta:
      author = "threatintel@volexity.com"
      date = "2021-03-01"
      description = "variation on reGeorgtunnel"
      hash = "406b680edc9a1bb0e2c7c451c56904857848b5f15570401450b73b232ff38928"
      reference = "https://github.com/sensepost/reGeorg/blob/master/tunnel.aspx"
   strings:
      $s1 = "System.Net.Sockets"
      $s2 = "System.Text.Encoding.Default.GetString(Convert.FromBase64String(StrTr(Request.Headers.Get"
      $t1 = ".Split('|')"
      $t2 = "Request.Headers.Get"
      $t3 = ".Substring("
      $t4 = "new Socket("
      $t5 = "IPAddress ip;"
   condition:
      all of ($s*) or
      all of ($t*)
}

rule WEBSHELL_ASPX_SportsBall : Webshell {
   meta:
      author = "threatintel@volexity.com"
      date = "2021-03-01"
      description = "The SPORTSBALL webshell allows attackers to upload files or execute commands on the system."
      hash = "2fa06333188795110bba14a482020699a96f76fb1ceb80cbfa2df9d3008b5b0a"
      reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
   strings:
      $uniq1 = "HttpCookie newcook = new HttpCookie(\"fqrspt\", HttpContext.Current.Request.Form"
      $uniq2 = "ZN2aDAB4rXsszEvCLrzgcvQ4oi5J1TuiRULlQbYwldE="

      $var1 = "Result.InnerText = string.Empty;"
      $var2 = "newcook.Expires = DateTime.Now.AddDays("
      $var3 = "System.Diagnostics.Process process = new System.Diagnostics.Process();"
      $var4 = "process.StandardInput.WriteLine(HttpContext.Current.Request.Form[\""
      $var5 = "else if (!string.IsNullOrEmpty(HttpContext.Current.Request.Form[\""
      $var6 = "<input type=\"submit\" value=\"Upload\" />"
   condition:
      any of ($uniq*) or
      all of ($var*)
}

rule WEBSHELL_CVE_2021_27065_Webshells {
   meta:
      description = "Detects web shells dropped by CVE-2021-27065. All actors, not specific to HAFNIUM. TLP:WHITE"
      author = "Joe Hannon, Microsoft Threat Intelligence Center (MSTIC)"
      date = "2021-03-05"
      reference = "https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/"
   strings:
      $script1 = "script language" ascii wide nocase
      $script2 = "page language" ascii wide nocase
      $script3 = "runat=\"server\"" ascii wide nocase
      $script4 = "/script" ascii wide nocase
      $externalurl = "externalurl" ascii wide nocase
      $internalurl = "internalurl" ascii wide nocase
      $internalauthenticationmethods = "internalauthenticationmethods" ascii wide nocase
      $extendedprotectiontokenchecking = "extendedprotectiontokenchecking" ascii wide nocase
   condition:
      filesize < 50KB and any of ($script*) and ($externalurl or $internalurl) and $internalauthenticationmethods and $extendedprotectiontokenchecking
}

rule APT_MAL_ASPX_HAFNIUM_Chopper_Mar21_3 {
   meta:
      description = "Detects HAFNIUM ASPX files dropped on compromised servers"
      author = "Florian Roth"
      reference = "https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/"
      date = "2021-03-07"
      score = 85
   strings:
      $s1 = "runat=\"server\">void Page_Load(object" ascii wide 
      $s2 = "Request.Files[0].SaveAs(Server.MapPath(" ascii wide
   condition:
      filesize < 50KB and
      all of them
}

rule APT_MAL_ASPX_HAFNIUM_Chopper_Mar21_4 {
   meta:
      description = "Detects HAFNIUM ASPX files dropped on compromised servers"
      author = "Florian Roth"
      reference = "https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/"
      date = "2021-03-07"
      score = 85
   strings:
      $s1 = "<%@Page Language=\"Jscript\"%>" ascii wide nocase
      $s2 = ".FromBase64String(" ascii wide nocase
      $s3 = "eval(System.Text.Encoding." ascii wide nocase
   condition:
      filesize < 850 and
      all of them
}

rule APT_HAFNIUM_ForensicArtefacts_WER_Mar21_1 {
   meta:
      description = "Detects a Windows Error Report (WER) that indicates and exploitation attempt of the Exchange server as described in CVE-2021-26857 after the corresponding patches have been applied. WER files won't be written upon successful exploitation before applying the patch. Therefore, this indicates an unsuccessful attempt."
      author = "Florian Roth"
      reference = "https://twitter.com/cyb3rops/status/1368471533048446976"
      date = "2021-03-07"
      score = 40
   strings:
      $s1 = "AppPath=c:\\windows\\system32\\inetsrv\\w3wp.exe" wide fullword
      $s7 = ".Value=w3wp#MSExchangeECPAppPool" wide
   condition:
      uint16(0) == 0xfeff and
      filesize < 8KB and
      all of them
}

rule EXPL_LOG_CVE_2021_27065_Exchange_Forensic_Artefacts_Mar21_1 : LOG {
   meta:
      description = "Detects forensic artefacts found in HAFNIUM intrusions exploiting CVE-2021-27065"
      author = "Florian Roth"
      reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
      date = "2021-03-02"
   strings:
      $s1 = "S:CMD=Set-OabVirtualDirectory.ExternalUrl='" ascii wide fullword
   condition:
      1 of them
}

rule EXPL_LOG_CVE_2021_26858_Exchange_Forensic_Artefacts_Mar21_1 : LOG {
   meta:
      description = "Detects forensic artefacts found in HAFNIUM intrusions exploiting CVE-2021-26858"
      author = "Florian Roth"
      reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
      date = "2021-03-02"
      score = 65
      modified = "2021-03-04"
   strings:
      $xr1 = /POST (\/owa\/auth\/Current\/themes\/resources\/logon\.css|\/owa\/auth\/Current\/themes\/resources\/owafont_ja\.css|\/owa\/auth\/Current\/themes\/resources\/lgnbotl\.gif|\/owa\/auth\/Current\/themes\/resources\/owafont_ko\.css|\/owa\/auth\/Current\/themes\/resources\/SegoeUI-SemiBold\.eot|\/owa\/auth\/Current\/themes\/resources\/SegoeUI-SemiLight\.ttf|\/owa\/auth\/Current\/themes\/resources\/lgnbotl\.gif)/   
   condition:
      $xr1
}

rule LOG_APT_HAFNIUM_Exchange_Log_Traces_Mar21_1 : LOG {
   meta:
      description = "Detects suspicious log entries that indicate requests as described in reports on HAFNIUM activity"
      author = "Florian Roth"
      reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
      date = "2021-03-04"
      score = 65
   strings:
      $xr1 = /POST \/(ecp\/y\.js|ecp\/main\.css|ecp\/default\.flt|ecp\/auth\/w\.js|owa\/auth\/w\.js)[^\n]{100,600} (200|301|302) /

      $xr3 = /POST \/owa\/auth\/Current\/[^\n]{100,600} (DuckDuckBot\/1\.0;\+\(\+http:\/\/duckduckgo\.com\/duckduckbot\.html\)|facebookexternalhit\/1\.1\+\(\+http:\/\/www\.facebook\.com\/externalhit_uatext\.php\)|Mozilla\/5\.0\+\(compatible;\+Baiduspider\/2\.0;\+\+http:\/\/www\.baidu\.com\/search\/spider\.html\)|Mozilla\/5\.0\+\(compatible;\+Bingbot\/2\.0;\+\+http:\/\/www\.bing\.com\/bingbot\.htm\)|Mozilla\/5\.0\+\(compatible;\+Googlebot\/2\.1;\+\+http:\/\/www\.google\.com\/bot\.html|Mozilla\/5\.0\+\(compatible;\+Konqueror\/3\.5;\+Linux\)\+KHTML\/3\.5\.5\+\(like\+Gecko\)\+\(Exabot-Thumbnails\)|Mozilla\/5\.0\+\(compatible;\+Yahoo!\+Slurp;\+http:\/\/help\.yahoo\.com\/help\/us\/ysearch\/slurp\)|Mozilla\/5\.0\+\(compatible;\+YandexBot\/3\.0;\+\+http:\/\/yandex\.com\/bots\)|Mozilla\/5\.0\+\(X11;\+Linux\+x86_64\)\+AppleWebKit\/537\.36\+\(KHTML,\+like\+Gecko\)\+Chrome\/51\.0\.2704\.103\+Safari\/537\.3)/
      $xr4 = /POST \/ecp\/[^\n]{100,600} (ExchangeServicesClient\/0\.0\.0\.0|python-requests\/2\.19\.1|python-requests\/2\.25\.1)[^\n]{200,600} (200|301|302) /
      $xr5 = /POST \/(aspnet_client|owa)\/[^\n]{100,600} (antSword\/v2\.1|Googlebot\/2\.1\+\(\+http:\/\/www\.googlebot\.com\/bot\.html\)|Mozilla\/5\.0\+\(compatible;\+Baiduspider\/2\.0;\+\+http:\/\/www\.baidu\.com\/search\/spider\.html\))[^\n]{200,600} (200|301|302) /
   condition:
      1 of them
}

rule LOG_Exchange_Forensic_Artefacts_CleanUp_Activity_Mar21_1 : LOG {
   meta:
      description = "Detects forensic artefacts showing cleanup activity found in HAFNIUM intrusions exploiting"
      author = "Florian Roth"
      reference = "https://twitter.com/jdferrell3/status/1368626281970024448"
      date = "2021-03-08"
      score = 70
   strings:
      $x1 = "cmd.exe /c cd /d C:/inetpub/wwwroot/aspnet_client" ascii wide
      $x2 = "cmd.exe /c cd /d C:\\inetpub\\wwwroot\\aspnet_client" ascii wide
      
      $s1 = "aspnet_client&del '"
      $s2 = "aspnet_client&attrib +h +s +r "
      $s3 = "&echo [S]"
   condition:
      1 of ($x*) or 2 of them
}

rule EXPL_LOG_CVE_2021_27055_Exchange_Forensic_Artefacts : LOG {
   meta:
      description = "Detects suspicious log entries that indicate requests as described in reports on HAFNIUM activity"
      author = "Zach Stanford - @svch0st, Florian Roth"
      reference = "https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/#scan-log"
      reference_2 = "https://www.praetorian.com/blog/reproducing-proxylogon-exploit/"
      date = "2021-03-10"
      score = 65
   strings:
      $x1 = "ServerInfo~" ascii wide

      $sr1 = /\/ecp\/[a-zA-Z0-9]\.js/ ascii wide

      $s1 = "/ecp/auth/w.js" ascii wide 
      $s2 = "/owa/auth/w.js" ascii wide
      $s3 = "/owa/auth/x.js" ascii wide
      $s4 = "/ecp/main.css" ascii wide
      $s5 = "/ecp/default.flt" ascii wide
      $s6 = "/owa/auth/Current/themes/resources/logon.css" ascii wide
   condition:
      $x1 and 1 of ($s*)
}

rule LOG_CVE_2021_27055_Exchange_Forensic_Artefacts_Mar21_2 : LOG {
   meta:
      description = "Detects suspicious log entries that indicate requests as described in reports on HAFNIUM activity"
      author = "Florian Roth"
      reference = "https://www.praetorian.com/blog/reproducing-proxylogon-exploit/"
      date = "2021-03-10"
      score = 65
   strings:
      $sr1 = /GET \/rpc\/ &CorrelationID=<empty>;&RequestId=[^\n]{40,600} (200|301|302)/
   condition:
      $sr1
}
