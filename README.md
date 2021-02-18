# Get-Autodiscover
 Retrieves client configuration for Exchange from Autodiscover service.

## Examples
# retrieve Autodiscover data using OAuth and raw response from service
```
.\Get-Autodiscover.ps1 -EmailAddress MeganB@contoso.com -Verbose -UseOAuth -RawResponse
```

# retrieve Autodiscover data using OAuth query Active Directory fro SCP
```
.\Get-Autodiscover.ps1 -EmailAddress MeganB@contoso.com -Verbose -UseOAuth -FromAD
```

# retrieve Autodiscover data using specific credential and server
```
.\Get-Autodiscover.ps1 -EmailAddress MeganB@contoso.com -Verbose -Credentials (Get-Credential) -Server autodiscover.contoso.com
```

## Required Parameters

### -EmailAddress

The required parameter EmailAddress defines the e-mail address for the object we want the configuration.

## Optional Parameters

### -Server

This parameter Server overrides the automation process of finding the Autodiscover endpoint. This is the hostname you will send the request to. Note: Cannot be used in combination with FromAD.

### -Credentials

The parameter Credentials accepts PSCredential objects, which are used for authentication. If ommited and no OAuth is used, the scripts runs in the context of the executing user.

### -SOAP

The parameter SOAP will cause to send SOAP requested instead of POX.

### -FromAD

The parameter FromAD will cause the secipt to query AD for SCP in order to find the Autodiscover endpoint. Note: Cannot be used in combination with Server.

### -ADSite

The parameter ADSite defines which ADSite will be queried. Note: Can only be used in combination with FromAD.

### -Timeout

The parameter Timeout defines the Timeout of the request.

### -TrustAll

The parameter TrustAll will disable certificate check.

### -UseOAuth

The parameter UseOAuth will trigger OAuth2 auth code flow for authentication.

### -RawResponse

The parameter RawResponse will return the raw response.

## Links

### [My Blog](https://ingogegenwarth.wordpress.com/)

### [Exchange Autodiscover Service Dev Reference](https://docs.microsoft.com/exchange/client-developer/web-service-reference/autodiscover-web-service-reference-for-exchange)

### [Exchange CAS Architecture Autodiscover](https://docs.microsoft.com/exchange/architecture/client-access/autodiscover)

## License

This project is licensed under the MIT License - see the LICENSE.md for details.