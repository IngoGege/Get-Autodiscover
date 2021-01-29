<#
    .SYNOPSIS
        This script is intended to retrieve configuration settings from Exchange Autodiscover service.
    .DESCRIPTION
        This script will query Exchange Autodiscover service for a given e-mail address and requests either POX or SOAP response.
    .PARAMETER EmailAddress
        The parameter EmailAddress defines the e-mail address for the object we want the configuration.
    .PARAMETER Server
        This required parameter Server overrides the automation process of finding the Autodiscover endpoint. This is the hostname you will send the request to. Note: Cannot be used in combination with FromAD.
    .PARAMETER Credentials
        The parameter Credentials accepts PSCredential objects, which are used for authentication. If ommited and no OAuth is used, the scripts runs in the context of the executing user.
    .PARAMETER SOAP
        The parameter SOAP will cause to send SOAP requested instead of POX.
    .PARAMETER FromAD
        The parameter FromAD will cause the secipt to query AD for SCP in order to find the Autodiscover endpoint. Note: Cannot be used in combination with Server.
    .PARAMETER ADSite
        The parameter ADSite defines which ADSite will be queried. Note: Can only be used in combination with FromAD.
    .PARAMETER Timeout
        The parameter Timeout defines the Timeout of the request.
    .PARAMETER TrustAll
        The parameter TrustAll will disable certificate check.
    .PARAMETER UseOAuth
        The parameter UseOAuth will trigger OAuth2 auth code flow for authentication.
    .PARAMETER RawResponse
        The parameter RawResponse will return the raw response.
    .EXAMPLE
        # retrieve Autodiscover data using OAuth and raw response from service
        .\Get-Autodiscover.ps1 -EmailAddress MeganB@contoso.com -Verbose -UseOAuth -RawResponse
        # retrieve Autodiscover data using OAuth query Active Directory fro SCP
        .\Get-Autodiscover.ps1 -EmailAddress MeganB@contoso.com -Verbose -UseOAuth -FromAD
        # retrieve Autodiscover data using specific credential and server
        .\Get-Autodiscover.ps1 -EmailAddress MeganB@contoso.com -Verbose -Credentials (Get-Credential) -Server autodiscover.contoso.com
    .NOTES

    .LINK
        https://ingogegenwarth.wordpress.com/
        https://docs.microsoft.com/exchange/client-developer/web-service-reference/autodiscover-web-service-reference-for-exchange
        https://docs.microsoft.com/exchange/architecture/client-access/autodiscover
#>
[CmdletBinding()]
param (
    [parameter(
        Mandatory=$true,
        Position=0)]
    [System.String]
    $EmailAddress,

    [parameter(
        Mandatory=$false,
        Position=1)]
    [System.String]
    $Server,

    [parameter(
        Mandatory=$false,
        Position=2)]
    [System.Management.Automation.PsCredential]
    $Credentials,

    [parameter(
        Mandatory=$false,
        Position=3)]
    [System.Management.Automation.SwitchParameter]
    $SOAP,

    [parameter(
        Mandatory=$false,
        Position=4)]
    [System.Management.Automation.SwitchParameter]
    $FromAD,

    [parameter(
        Mandatory=$false,
        Position=5)]
    [System.String]
    $ADSite,

    [parameter(
        Mandatory=$false,
        Position=6)]
    [System.Int16]
    $Timeout = 20,

    [parameter(
        Mandatory=$false,
        Position=7)]
    [System.Management.Automation.SwitchParameter]
    $TrustAll,

    [parameter(
        Mandatory=$false,
        Position=8)]
    [System.Management.Automation.SwitchParameter]
    $UseOAuth,

    [parameter(
        Mandatory=$false,
        Position=9)]
    [System.Management.Automation.SwitchParameter]
    $RawResponse

    )

begin
{

    #check for ambiguous combinations
    if ($Server -and $FromAD)
    {
        Write-Warning "Please use either a server or let the script search AD for SCP, but not both!"
        break
    }

    if ($ADSite -and -not $FromAD)
    {
        Write-Warning "ADSite will be ignored if FromAD is not used!"
    }

    $headersAutoD = @{}
    $headersAutoD.Add('X-MapiHttpCapability','1')
    $headersAutoD.Add('X-ClientCanHandle','Negotiate,ExHttpInfo')

    $targetDomain = $EmailAddress.Split('@')[1]

    # thanks to https://gsexdev.blogspot.com/
    function Show-OAuthWindow {
        [CmdletBinding()]
        param (
            [System.Uri]
            $Url

        )
        ## Start Code Attribution
        ## Show-AuthWindow function is the work of the following Authors and should remain with the function if copied into other scripts
        ## https://foxdeploy.com/2015/11/02/using-powershell-and-oauth/
        ## https://blogs.technet.microsoft.com/ronba/2016/05/09/using-powershell-and-the-office-365-rest-api-with-oauth/
        ## End Code Attribution
        Add-Type -AssemblyName System.Web
        Add-Type -AssemblyName System.Windows.Forms

        $form = New-Object -TypeName System.Windows.Forms.Form -Property @{ Width = 440; Height = 640 }
        $web = New-Object -TypeName System.Windows.Forms.WebBrowser -Property @{ Width = 420; Height = 600; Url = ($url) }
        $Navigated = {
            if ( ($web.DocumentText -match "document.location.replace") -or ($web.Url.AbsoluteUri -match "code=[^&]*") ) {
                $Script:oAuthCode = [regex]::match($web.DocumentText, "code=(.*?)\\u0026").Groups[1].Value
                if ([System.String]::IsNullOrEmpty($Script:oAuthCode))
                {
                    if ($web.Url.AbsoluteUri -match "error=[^&]*")
                    {
                        $Script:oAuthCode = [System.Web.HttpUtility]::UrlDecode($web.Url.AbsoluteUri)
                    }
                    else
                    {
                        $Script:oAuthCode = [System.Web.HttpUtility]::ParseQueryString($web.Url.AbsoluteUri)[0]
                    }
                }
                $form.Close();
            }
        }
        $web.ScriptErrorsSuppressed = $true
        $web.Add_Navigated($Navigated)
        $form.Controls.Add($web)
        $form.Add_Shown( { $form.Activate() })
        $form.ShowDialog() | Out-Null
        return $Script:oAuthCode
    }

    function TrustAllCerts
    {
        # Code From http://poshcode.org/624
        # Create a compilation environment
        $Provider=New-Object Microsoft.CSharp.CSharpCodeProvider
        $Compiler=$Provider.CreateCompiler()
        $Params=New-Object System.CodeDom.Compiler.CompilerParameters
        $Params.GenerateExecutable=$False
        $Params.GenerateInMemory=$True
        $Params.IncludeDebugInformation=$False
        $Params.ReferencedAssemblies.Add("System.DLL") | Out-Null
        $TASource=@'
        namespace Local.ToolkitExtensions.Net.CertificatePolicy{
            public class TrustAll : System.Net.ICertificatePolicy {
            public TrustAll() {
            }
            public bool CheckValidationResult(System.Net.ServicePoint sp,
                System.Security.Cryptography.X509Certificates.X509Certificate cert,
                System.Net.WebRequest req, int problem) {
                return true;
            }
            }
        }
'@
        $TAResults=$Provider.CompileAssemblyFromSource($Params,$TASource)
        $TAAssembly=$TAResults.CompiledAssembly
        # We now create an instance of the TrustAll and attach it to the ServicePointManager
        $TrustAll=$TAAssembly.CreateInstance("Local.ToolkitExtensions.Net.CertificatePolicy.TrustAll")
        [System.Net.ServicePointManager]::CertificatePolicy=$TrustAll
        # end code from http://poshcode.org/624
    }

    function Get-AutoDV2
    {
        [CmdletBinding()]
        Param (
        [Parameter(
            Mandatory=$true,
            Position=0)]
        [System.String]
        $EmailAddress,

        [Parameter(
            Mandatory=$false,
            Position=1)]
        [System.String]
        $Server,

        [Parameter(
            Mandatory=$true,
            Position=2)]
        [ValidateSet("Actions","ActiveSync","AutodiscoverV1","Connectors","ConnectorsProcessors","ConnectorsWebhook","Ews","NotesClient","OutlookCloudSettingsService","OutlookLocationsService","OutlookMeetingScheduler","OutlookPay","OutlookTailoredExperiences","OwaPoweredExperience","OwaPoweredExperienceV2","Rest","Substrate","SubstrateNotificationService","SubstrateSearchService","ToDo","Weve")]
        [System.String]
        $Protocol

        )
        try{
            if ($Server)
            {
                $URL = "https://$server/autodiscover/autodiscover.json?Email=$EmailAddress&Protocol=$Protocol"
            }
            else
            {
                $URL = "https://autodiscover-s.outlook.com/autodiscover/autodiscover.json?Email=$EmailAddress&Protocol=$Protocol"
            }

            Write-Verbose "URL=$($Url)"
            Invoke-RestMethod -Uri $Url
        }
        catch{
            $_
        }
    }

    if ($UseOAuth)
    {
        # acquiring an access token using Microsoft Office application
        try {
            Add-Type -AssemblyName System.Web
            [System.Uri]$autoDV1Uri= (Get-AutoDV2 -EmailAddress $EmailAddress -Protocol AutodiscoverV1).Url

            if ($Server)
            {
                $audience = 'https://' + $Server
            }
            else
            {
                $audience = 'https://' + $autoDV1Uri.Authority
            }

            # parameters for auth code flow
            $RedirectURI = 'urn:ietf:wg:oauth:2.0:oob'
            $ClientID = 'd3590ed6-52b3-4102-aeff-aad2292ab01c'
            $state = Get-Random
            $authURI = "https://login.microsoftonline.com/Common"
            $authURI += "/oauth2/authorize?client_id=$ClientId"
            $authURI += "&response_type=code&redirect_uri= " + [System.Web.HttpUtility]::UrlEncode($RedirectURI)
            $authURI += "&response_mode=query&resource=" + [System.Web.HttpUtility]::UrlEncode($audience) + "&state=$state"
            $authURI += "&prompt=select_account"

            # acquire auth code from AAD
            $authCode = Show-OAuthWindow -Url $authURI

            # if error occured stop
            if ($authCode -match 'error_description')
            {
                Write-Host "Error requesting Auth Code:$($authCode)"
                break
            }

            # acquire access token
            if (-not [System.String]::IsNullOrEmpty($authCode))
            {
                $body = @{"grant_type" = "authorization_code"; "scope" = $scopes; "client_id" = "$ClientId"; "code" = $authCode; "redirect_uri" = $RedirectURI }

                $tokenRequest = Invoke-RestMethod -Method Post -ContentType application/x-www-form-urlencoded -Uri "https://login.microsoftonline.com/$targetDomain/oauth2/v2.0/token" -Body $body
                $Script:accessToken = $tokenRequest.access_token
            }

            # add access token to header
            $headersAutoD.Add('Authorization', "Bearer $($Script:accessToken)")

        }
        catch {
            $_
            break
        }
    }

    if ($TrustAll)
    {
        Write-Host -fore yellow 'Configure to trust all certificates!'
        TrustAllCerts
    }

    if ($FromAD) {
        #check if computer is domain joined
        if ((gwmi win32_computersystem).partofdomain)
        {
            if (-not ($ADSite))
            {
                $ADSite = "$(([System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite()).GetDirectoryEntry().Name)"
            }

            $filter = "(&(objectClass=serviceConnectionPoint)(|(keywords=67661d7F-8FC4-4fa7-BFAC-E1D7794C1F68)(keywords=77378F46-2C66-4aa9-A6A6-3E7A48B19596)))"
            $root= ([ADSI]'LDAP://RootDse').configurationNamingContext
            $searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$root")
            $searcher.filter = $filter
            $searcher.pagesize = 1000
            $results = $searcher.findall()
            if ($results)
            {
                #all SCPs
                $SCPs = $results | select @{l="Name";e={$_.Properties.name}},@{l="Created";e={$_.Properties.whencreated}},@{l="Key";e={$_.properties.keywords}},@{l="Link";e={$_.Properties.servicebindinginformation}} | sort created 
                #first check for matching AD site
                $matchADSite = $SCPs | ?{$_.Key | ?{$_.Split('=')[1] -contains $ADSite}}
                #second check wildcard site
                if (-not ($matchADSite))
                {
                    Write-Host -fore red "No match for ADSite $($ADSite)!"
                    #last pick the oldest one from all found
                    if ( $SCPs | ?{$_.Key -match 'Site'} )
                    {
                        $Server = ($SCPs | select -First 1).Link.Split('//')[2]
                        $SCPs | select -First 1 | fl
                    }
                }
                else
                {
                    Write-Host "Using oldest SCP!"
                    $matchADSite | select -First 1 | fl
                    $Server = ($matchADSite | select -First 1).Link.Split('//')[2]
                }

                if ($Server)
                {
                    Write-Host "Using server $($server)!"
                }
                else {
                    Write-Host -fore yellow "Will try to get answer from Autodiscover and not from SCP!"
                }
            }
            else
            {
                Write-host -fore red "Couldn't retrieve data from AD!"
                break
            }
        }
        else
        {
            Write-Host -for red "Sorry, computer is not domain joined and cannot get SCP from AD!`nWill try without SCP!"
        }

    }

    if ($Server)
    {
        $target = $Server
    }
    elseif ($audience)
    {
        $target = $autoDV1Uri.Authority
    }
    else
    {
        Write-Host -fore yellow "No server specified! Will try to figure out!"
        $domain = $EmailAddress.Split("@")[1]
        $target = 'autodiscover.' + $domain
    }

    if ($SOAP)
    {
        [System.Uri]$URL = "https://$target/autodiscover/autodiscover.svc"
    }
    else
    {
        [System.Uri]$URL = "https://$target/autodiscover/autodiscover.xml"
    }

}

process
{
    if ($SOAP)
    {
        $autoDRequest = '
        <soap:Envelope xmlns:a="http://schemas.microsoft.com/exchange/2010/Autodiscover"
                       xmlns:wsa="http://www.w3.org/2005/08/addressing" 
                       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                       xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
        <soap:Header>
            <a:RequestedServerVersion>Exchange2010</a:RequestedServerVersion>
            <wsa:Action>http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetUserSettings</wsa:Action>
        </soap:Header>
        <soap:Body>
            <a:GetUserSettingsRequestMessage xmlns:a="http://schemas.microsoft.com/exchange/2010/Autodiscover">
            <a:Request>
                <a:Users>
                    <a:User>
                        <a:Mailbox>'
        $autoDRequest += $EmailAddress
        $autoDRequest += '</a:Mailbox>
                    </a:User>
                </a:Users>
                    <a:RequestedSettings>
                        <a:Setting>UserDisplayName</a:Setting>
                        <a:Setting>UserDN</a:Setting>
                        <a:Setting>UserDeploymentId</a:Setting>
                        <a:Setting>InternalMailboxServer</a:Setting>
                        <a:Setting>InternalRpcClientServer</a:Setting>
                        <a:Setting>InternalMailboxServerDN</a:Setting>
                        <a:Setting>InternalEcpUrl</a:Setting>
                        <a:Setting>InternalEcpVoicemailUrl</a:Setting>
                        <a:Setting>InternalEcpEmailSubscriptionsUrl</a:Setting>
                        <a:Setting>InternalEcpTextMessagingUrl</a:Setting>
                        <a:Setting>InternalEcpDeliveryReportUrl</a:Setting>
                        <a:Setting>InternalEcpRetentionPolicyTagsUrl</a:Setting>
                        <a:Setting>InternalEcpPublishingUrl</a:Setting>
                        <a:Setting>InternalEwsUrl</a:Setting>
                        <a:Setting>InternalOABUrl</a:Setting>
                        <a:Setting>InternalUMUrl</a:Setting>
                        <a:Setting>InternalWebClientUrls</a:Setting>
                        <a:Setting>MailboxDN</a:Setting>
                        <a:Setting>PublicFolderServer</a:Setting>
                        <a:Setting>ActiveDirectoryServer</a:Setting>
                        <a:Setting>ExternalMailboxServer</a:Setting>
                        <a:Setting>ExternalMailboxServerRequiresSSL</a:Setting>
                        <a:Setting>ExternalMailboxServerAuthenticationMethods</a:Setting>
                        <a:Setting>EcpVoicemailUrlFragment</a:Setting>
                        <a:Setting>EcpEmailSubscriptionsUrlFragment</a:Setting>
                        <a:Setting>EcpTextMessagingUrlFragment</a:Setting>
                        <a:Setting>EcpDeliveryReportUrlFragment</a:Setting>
                        <a:Setting>EcpRetentionPolicyTagsUrlFragment</a:Setting>
                        <a:Setting>EcpPublishingUrlFragment</a:Setting>
                        <a:Setting>ExternalEcpUrl</a:Setting>
                        <a:Setting>ExternalEcpVoicemailUrl</a:Setting>
                        <a:Setting>ExternalEcpEmailSubscriptionsUrl</a:Setting>
                        <a:Setting>ExternalEcpTextMessagingUrl</a:Setting>
                        <a:Setting>ExternalEcpDeliveryReportUrl</a:Setting>
                        <a:Setting>ExternalEcpRetentionPolicyTagsUrl</a:Setting>
                        <a:Setting>ExternalEcpPublishingUrl</a:Setting>
                        <a:Setting>ExternalEwsUrl</a:Setting>
                        <a:Setting>ExternalOABUrl</a:Setting>
                        <a:Setting>ExternalUMUrl</a:Setting>
                        <a:Setting>ExternalWebClientUrls</a:Setting>
                        <a:Setting>CrossOrganizationSharingEnabled</a:Setting>
                        <a:Setting>AlternateMailboxes</a:Setting>
                        <a:Setting>CasVersion</a:Setting>
                        <a:Setting>EwsSupportedSchemas</a:Setting>
                        <a:Setting>InternalPop3Connections</a:Setting>
                        <a:Setting>ExternalPop3Connections</a:Setting>
                        <a:Setting>InternalImap4Connections</a:Setting>
                        <a:Setting>ExternalImap4Connections</a:Setting>
                        <a:Setting>InternalSmtpConnections</a:Setting>
                        <a:Setting>ExternalSmtpConnections</a:Setting>
                        <a:Setting>InternalServerExclusiveConnect</a:Setting>
                        <a:Setting>ExternalServerExclusiveConnect</a:Setting>
                        <a:Setting>ExchangeRpcUrl</a:Setting>
                        <a:Setting>ShowGalAsDefaultView</a:Setting>
                        <a:Setting>AutoDiscoverSMTPAddress</a:Setting>
                        <a:Setting>InteropExternalEwsUrl</a:Setting>
                        <a:Setting>ExternalEwsVersion</a:Setting>
                        <a:Setting>InteropExternalEwsVersion</a:Setting>
                        <a:Setting>MobileMailboxPolicyInterop</a:Setting>
                        <a:Setting>GroupingInformation</a:Setting>
                        <a:Setting>UserMSOnline</a:Setting>
                        <a:Setting>MapiHttpEnabled</a:Setting>
                    </a:RequestedSettings>
                </a:Request>
                </a:GetUserSettingsRequestMessage>
            </soap:Body>
        </soap:Envelope>
    '

    $fedRequest = '<?xml version="1.0" encoding="utf-8"?>
        <soap:Envelope
            xmlns:exm="http://schemas.microsoft.com/exchange/services/2006/messages"
            xmlns:ext="http://schemas.microsoft.com/exchange/services/2006/types"
            xmlns:a="http://www.w3.org/2005/08/addressing"
            xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
            xmlns:xsd="http://www.w3.org/2001/XMLSchema">
            <soap:Header>
                <a:Action soap:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action>
                <a:To soap:mustUnderstand="1">https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc</a:To>
                <a:ReplyTo>
                    <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
                </a:ReplyTo>
            </soap:Header>
            <soap:Body>
                <GetFederationInformationRequestMessage
                    xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
                    <Request>
                        <Domain>'
    $fedRequest += $targetDomain
    $fedRequest += '</Domain>
                    </Request>
                </GetFederationInformationRequestMessage>
            </soap:Body>
        </soap:Envelope>'

    }
    else
    {
    $autoDRequest = '<?xml version="1.0" encoding="utf-8"?>
        <Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
            <Request>
                <EMailAddress>'

    $autoDRequest += $EmailAddress

    $autoDRequest += '</EMailAddress>
                      <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
            </Request>
        </Autodiscover>
        '

    }

    # create parameters for Invoke-WebRequest
    $autoDRequestParams = @{
        Uri = $URL.AbsoluteUri
        Method = 'POST'
        Body = $autoDRequest
        ContentType = "text/xml; charset=utf-8"
        Headers = $headersAutoD
        TimeoutSec = $Timeout
    }

    $fedRequestParams = @{
        Uri = 'https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc'
        Method = 'POST'
        Body = $fedRequest
        ContentType = "text/xml; charset=utf-8"
        UserAgent = 'AutodiscoverClient'
        TimeoutSec = $Timeout
    }

    if ($Credentials) {
        $autoDRequestParams.Add('Credential',$Credentials)
    }

    if (-not $UseOAuth -AND -not $Credentials) {
        $autoDRequestParams.Add('UseDefaultCredentials',$true)
    }

    try {
        # send AutoD request
        $autoDResponse = Invoke-WebRequest @autoDRequestParams
        if ($SOAP)
        {
            # send Fed request
            $fedResponse = Invoke-WebRequest @fedRequestParams
        }
    }
    catch {
        $_
        break
    }

}

end
{
    if ($RawResponse)
    {
        $autoDResponse
        $fedResponse
    }
    else
    {
        $root = ([XML]$autoDResponse).Get_DocumentElement()

        if ($SOAP)
        {
            if (-not [System.String]::IsNullOrEmpty($autoDResponse) )
            {
                $outputObject = New-Object -TypeName psobject
                $items = $root.Body.GetElementsByTagName("UserSetting") |  Select-Object -Property Name,Value
                foreach ($item in $items)
                {
                    $outputObject | Add-Member -MemberType NoteProperty -Name $( $item.Name ) -Value $( $item.Value )
                }
                $outputObject | Add-Member -MemberType NoteProperty -Name 'AlternateMailbox' -Value $( $root.Body.GetElementsByTagName("AlternateMailbox") )
                $outputObject | Add-Member -MemberType NoteProperty -Name 'UserSettingError' -Value $( $root.Body.GetElementsByTagName('UserSettingError') )
                $outputObject | Add-Member -MemberType NoteProperty -Name 'RedirectTarget' -Value $( $root.Body.GetElementsByTagName('RedirectTarget').'#text' )
                $outputObject | Add-Member -MemberType NoteProperty -Name 'ResponseHeaders' -Value $($autoDRequest.Headers)

                # parse GetFederationInformation and add to output
                $fedroot = ([XML]$fedResponse).Get_DocumentElement()

                $fedObject = New-Object -TypeName psobject
                $fedObject | Add-Member -MemberType NoteProperty -Name 'ApplicationUri' -Value $( $fedroot.Body.GetElementsByTagName('ApplicationUri').'#text' )
                $fedObject | Add-Member -MemberType NoteProperty -Name 'Domains' -Value $( $fedroot.Body.GetElementsByTagName('Domain').'#text' )
                $fedObject | Add-Member -MemberType NoteProperty -Name 'TokenIssuers' -Value $( $fedroot.Body.GetElementsByTagName('TokenIssuer') )

                $outputObject | Add-Member -MemberType NoteProperty -Name 'FederationInformation' -Value $($fedObject)

                $outputObject
            }
        }
        else
        {
            $root.Response.SelectNodes('*//*') | Select-Object @{l='Name';e={$_.name}},@{l='Value';e={$_.'#text'}}
        }
    }
}

