<#
.SYNOPSIS 
Gets the value of an AuthLite setting in the AuthLite data partition

.PARAMETER dc
Name of the server to use. If not specified, lets ADSI try to find a server
.PARAMETER name
Setting name

.EXAMPLE
GetPartitionSetting -name foo
#>

Function GetPartitionSetting()
{
	Param($dc, `
		$name
	)
	import-module ActiveDirectory
	$domdn = Get-ADDomain | select -ExpandProperty DistinguishedName            
	if($dc -ne $null)
	{
		$container = [ADSI] ("LDAP://$dc/CN=AuthLiteSettings,dc=AuthLite," + $domdn)
	}
	else
	{
		$container = [ADSI] ("LDAP://CN=AuthLiteSettings,dc=AuthLite," + $domdn)
	}
   $rev = 1
   try
   {
      return $container.Children.Find("cn=$name").Get("CollectiveAuthLiteSettingValue")
   }
   catch
   {
      $Error.Clear()
      return $null
   }
}

<#
.SYNOPSIS 
Sets the value of an AuthLite setting in the AuthLite data partition

.PARAMETER dc
Name of the server to use. If not specified, lets ADSI try to find a server
.PARAMETER name
Setting name
.PARAMETER value
String value for setting
.PARAMETER reload
$true to flush the settings cache on the local calling machine

.NOTES
Calling context must have write permission to the cn=AuthLiteSettings container.

.EXAMPLE
SetPartitionSetting -name foo -value "b a r" -reload $true
#>

Function SetPartitionSetting()
{
	Param($dc, `
		$name, `
		$value, `
		$reload `
	)
	import-module ActiveDirectory
	$domdn = Get-ADDomain | select -ExpandProperty DistinguishedName            
	if($dc -ne $null)
	{
		$container = [ADSI] ("LDAP://$dc/CN=AuthLiteSettings,dc=AuthLite," + $domdn)
	}
	else
	{
		$container = [ADSI] ("LDAP://CN=AuthLiteSettings,dc=AuthLite," + $domdn)
	}
   $rev = 1
   try
   {
      $rev = 0 + $container.Children.Find("cn=RevisionNumber").Get("CollectiveAuthLiteSettingValue")
   }
   catch
   {
	  $Error.Clear()
      $srev = $container.Create("CollectiveAuthLiteSetting", "cn=RevisionNumber")
      $srev.Put("CollectiveAuthLiteSettingValue", $rev)
      $srev.SetInfo()
   }
   #write-output "Current settings revision is $rev"
   $ex = $null
   try
   {
      $ex = $container.Children.Find("cn=$name")
   }
   catch 
   {
      $Error.Clear()
   }
   if($ex -eq $null)
   {
	 if($value -ne "null")
     {	
		$setting = $container.Create("CollectiveAuthLiteSetting", "cn=$name")
	 }
   }
   else
   {
     if($value -ne "null")
	 {
		$setting = $ex
     }
	 else
	 {
		$container.Delete("collectiveAuthLiteSetting", "cn=$name")
		$container.SetInfo()
	 }
   }
   if($value -ne "null")
   {
	   $setting.Put("CollectiveAuthLiteSettingValue", $value)
	   $setting.SetInfo()
   }
   $srev = $container.Children.Find("cn=RevisionNumber")
   $srev.Put("CollectiveAuthLiteSettingValue", 1+ $rev)
   $srev.SetInfo()
   write-output "Set $name to $value"
   if($reload -eq $true)
   {
		ReloadSettings
   }
}

<#
.SYNOPSIS 
Flush the AuthLite settings cache on the calling machine
#>
Function ReloadSettings()
{
	& "c:\Program Files\Collective Software\AuthLite\ReloadSettings.exe" 
	# because core holds up the reload event for 5 seconds; don't do anything else until after that long
	# (such as letting the caller keep going and do another setting write and another reload,
	# because the reload command would be skipped silently while the event is still high,
	# and the setting not actually updated in live, which is the point of testing)
	Write-Output "Wait for settings reload"
	Start-Sleep 6
}

<#
.SYNOPSIS 
Look up the group name and set its SID as the value of the specified AuthLite partition setting.

.PARAMETER name
The name of the partition setting
.PARAMETER group
The sAMAccountName of the security group

.NOTES
Calling context must have write permission to the CN=AuthLiteSettings container

.EXAMPLE
SetGroupSetting -name "CallIAUGroup" -group "AuthLite IAU Callers"
#>
Function SetGroupSetting()
{
	Param($name, $group, $reload)

	$gsid = (get-adgroup -filter {sAMAccountName -eq $group}).SID.Value
	write-output "Setting group for $name to $group ($gsid)"
	SetPartitionSetting -name $name -value $gsid -reload $reload
}
Function SetGroupPairSetting()
{
	Param($name, $group1, $group2, $reload)

	$g1sid = (get-adgroup -filter {sAMAccountName -eq $group1}).SID.Value
	$g2sid = (get-adgroup -filter {sAMAccountName -eq $group2}).SID.Value
	write-output "Setting group pair for $name to $group1 ($g1sid) | $group2 ($g2sid)"
	SetPartitionSetting -name $name -value "$g1sid|$g2sid" -reload (?: {$reload} {$true} {$false})
}

<#
.SYNOPSIS 
Lists the name and value of one or more AuthLite settings in the AuthLite data partition
which contain values matching a string

.PARAMETER contains
Settings whose values match this optional value will be returned

.EXAMPLE
FindPartitionSetting -containing rdp
#>
function FindPartitionSetting()
{
	Param($containing)
	
   import-module ActiveDirectory
   $domdn = Get-ADDomain | select -ExpandProperty DistinguishedName            
   $settings = "LDAP://CN=AuthLiteSettings,DC=AuthLite," + $domdn
   
   $searcher = New-Object adsisearcher
   if($containing -ne $null)
   {
      $searcher.Filter = "(collectiveAuthLiteSettingValue=*$containing*)"
   }
   else
   {
      $searcher.Filter = "(objectClass=collectiveAuthLiteSetting)"
   }
   $searcher.SearchRoot = $settings
   $searcher.PageSize = 1000
   $results = $searcher.FindAll()
   
   foreach($result in $results)
   {
       $setting = [ADSI]$result.Path
       foreach($item in $setting)
       {
          try
          {
                  [pscustomobject] @{
                     Name = $item.cn.ToString();
                     Value = $item.collectiveAuthLiteSettingValue.ToString()
                  }
          }
          catch
          {
             if($_.Exception.InnerException.GetType() -ne [System.ArgumentException])
             {
                write-output $_.Exception
             }
          }
       }
   }
}


<#
.SYNOPSIS 
Create a new token record, or associate an existing YubiKey to a user

.DESCRIPTION
Returns an enumerated type Collective.AuthLite.Protocol.AuthLiteProvisionStatus whose possible values are:
	Success
	GeneralError
	PermissionDenied
	InvalidOtpFormat
	KeyAlreadyAssociated
	SuccessButCouldNotAddToBootstrap

.PARAMETER domain 
Use the short (NETBIOS) domain
.PARAMETER username
Use the short (sAMAccountName) username
.PARAMETER password
AD password of the user, required if the calling context is provisioning a token for itself and not running as a token provisioner.
.PARAMETER description
For non-YubiKey tokens, set the Descriptive ID (this is shown in the data manager, and by convention also in the user's token app). Omit for YubiKeys.
.PARAMETER seed
For locally-stored OATH tokens, the 20-byte OATH secret as a 40-character hex string. Omit for YubiKeys.
.PARAMETER interval
For locally-stored OATH tokens, the number of seconds that the token's algorithm is programmed to use between changes. 
default=30. 
Typical values: 30 for soft tokens, 60 for hardware tokens.
.PARAMETER provisiontype
"New", unless associating an existing YubiKey record with a user, in which case use "Existing"
.PARAMETER tokentype
"YubiKeyOTP"		A YubiKey (newly programmed, or associate to existing).
"LocalOath"			An OATH token whose secret is stored on the DCs and validates "online" AD credentials.
"OathTimeSynced"	Same as above but token's clock is synced with reality (e.g. a soft token on a phone)
"OfflineOath"	An OATH token whose secret is pushed to workstations and can only be used for local (i.e. offline cached) authentication to those systems.
.PARAMETER bootstrap
$true to add the user to the configured "New Users Group" upon successful token creation
.PARAMETER aeskey
The 16-byte AES secret which has been programmed onto the YubiKey, as a 32-character hex string. Omit for other token types.
.PARAMETER publicid
The (by default) 16-byte static identifier for the YubiKey, as a (by default) 32-character hex string. Omit for other token types.
.PARAMETER serial
The serial number of this YubiKey. Omit for other token types and for provisiontype=existing
.PARAMETER challengeresponsesecret
The 20-bite HMAC/SHA-1 secret which has been programmed onto the YubiKey, as a 40-character hex string. Omit for other token types, or if YubiKey slot 2 has not been programmed.


.NOTES
This function does NOT program YubiKeys or generate QR codes etc. Its purpose is to create AuthLite Key records in the data store and/or associate them with users.

Calling context must be one of:
1) A Domain Admin 
2) The same user for whom the token is being provisioned AND either
	2a) Not an AuthLite User yet, or
	2b) calling from a 2-factor authenticated session
3) A member of the group specified in Administrative Groups -> Allowed to program and Import AuthLite keys

.EXAMPLE
ProvisionToken -provisiontype new -tokentype yubikeyotp -domain sandbox -username duser1 -serial 123456 -publicid "00000000000000000000000042424242" -aeskey "1277e34c4f584be8b1d1268d2c70af8c" -challengeresponsesecret "5641fabc2a2a196760dc12712ed934594861a9bc" -bootstrap $true
Provision a new YubiKey of specified seerial number that has been programmed with the specified ID and secrets, and associate it to the specified user, and add the user account to the configured "Group for New Users"

.EXAMPLE
ProvisionToken -provisiontype new -tokentype oathtimesynced -domain sandbox -username duser1 -description "duser1's token" -seed "5641fabc2a2a196760dc12712ed934594861a9bc" -bootstrap $true
Provision a new OATH token record of specified seed and the default interval (30s), and associate it to the specified user, and add the user account to the configured "Group for New Users"
#>
Function ProvisionToken
{
	Param($domain, `
		$username, `
		$password, `
		$description, `
		$seed, `
		$interval, `
		$provisiontype, `
		$tokentype, `
		$bootstrap, `
		$aeskey, `
		$publicid, `
		$serial, `
		$challengeresponsesecret)

	add-type -Path "c:\Program Files\Collective Software\AuthLite\CSALnetClient.dll"
	add-type -Path "c:\Program Files\Collective Software\AuthLite\Collective.AuthLite.Common.dll"
	add-type -Path "c:\Program Files\Collective Software\AuthLite\Collective.YubiAuth.dll"
	
	# $newKey = new-object Collective.AuthLite.DataStore.AuthLiteKey
	$preq = new-object Collective.AuthLite.Protocol.AuthLiteProvisionTokenRequest
	if($provisiontype -ne $null) {$preq.ProvisionType = [Collective.AuthLite.Protocol.AuthLiteProvisionTokenType] $provisiontype}
	if($tokentype -ne $null) {$preq.TokenType = [Collective.AuthLite.Protocol.AuthLiteTokenType] $tokentype}

	#always required, for historical dumb reasons
	$preq.PublicId = (?: {$publicid -eq $null} {[Collective.Security.CryptoUtil]::GetRandomBytes(16)} {[Collective.YubiAuth.Hex]::Decode($publicid)})
	$preq.AesKey = (?: {$aeskey -eq $null} {New-Object Byte[] 16} {[Collective.YubiAuth.Hex]::Decode($aeskey)})

	switch -wildcard ($preq.TokenType.ToString())
	{
		"YubiKeyOTP" 
		{
			if($serial -ne $null) {$preq.SerialNumber = $serial -as [int]}
			if($challengeresponsesecret -ne $null) {$preq.ChallengeResponseSecret = [Collective.YubiAuth.Hex]::Decode($challengeresponsesecret)}
		}
		"*Oath" 
		{
			$preq.DescriptiveID = $description
			$preq.OathDrift = (?: {$seed -eq $null} {0} {[Collective.AuthLite.Settings.Constants]::LDAP_MAX_INT})
			$preq.OathInterval = (?: {$interval -eq $null} {[Collective.AuthLite.Settings.Constants]::DEFAULT_OATH_INTERVAL_SECONDS} {$interval})
			$preq.OathSecret = (?: {$seed -eq $null} {[Collective.Security.CryptoUtil]::GetRandomBytes([Collective.AuthLite.Settings.Constants]::OATH_SECRET_BYTES)} {ParseSeed($seed)})
		}
	}
	$preq.BootstrapOperation = (?: {$bootstrap -eq $true} {[Collective.AuthLite.Protocol.AuthLiteBootstrapOperation]::Add} {[Collective.AuthLite.Protocol.AuthLiteBootstrapOperation]::None})
	# yes check username before setting domain; we always need domain specified in req for routing
	if($username -ne $null) {$preq.Domain = $domain}
	if($username -ne $null) {$preq.Username = $username}

	$req = new-object Collective.AuthLite.Protocol.AuthLiteInfrastructureRequest
	$req.Domain = $domain
	$req.ProvisionTokenRequest = $preq
	if($password -ne $null)
	{
		# provisioning as unprivileged user; prove they know the password for that account
		$req.PlainPassword = $password
	}

	try
	{
		$client = new-object Collective.AuthLite.CSALnetClient.Client
		$res = $client.ProcessRequest($req)
		#write-output "ProcessRequest did not throw"
		$pres = $res.ProvisionTokenResponse
		$eres = $res.ErrorMessage

		if($pres -ne $null)
		{
			if($pres.Status -eq [Collective.AuthLite.Protocol.AuthLiteProvisionStatus]::Success)
			{
				write-output ("Provision Succeeded: " + $pres.Status) # return this first
				#return $preq.OathSecret
			}
			else
			{
				write-output ("ProvisionStatus: " + $pres.Status) # return this first
			}
		}
		elseif($eres -ne $null)
		{
			write-output ("Provision operation returned error result: " + $eres.code)
			return $eres
		}
		else
		{
			write-error "Nothing in response"
		}
	}
	catch [Collective.AuthLite.CSALnetClient.LsaOperationException]
	{
		# http://www.vexasoft.com/blogs/powershell/7255220-powershell-tutorial-try-catch-finally-and-error-handling-in-powershell
		$m = $_.Exception.Message
		write-error "LSA exception: $m"
	}
	catch
	{
		$m = $_.Exception.Message
		write-error "exception: $m"
	}
}

<#
.SYNOPSIS 
Gets information about the hashed value of a user's PIN code, to be used for comparison

.DESCRIPTION
Returns an enumerated type Collective.AuthLite.Protocol.AuthLiteGetUserPinStatus whose possible values are:
	Success			The PIN record information has been returned
	NotFound		This user does not have a PIN record
If the caller does not have permission, an error is returned (via write-error)
.PARAMETER domain 
Use the short (NETBIOS) domain
.PARAMETER username
Use the short (sAMAccountName) username

.NOTES
Calling context must be one of:
1) A Domain Admin 
2) A member of the security group whose SID (without brackets) is stored in the partition setting "ReadUserPinsGroup" (does not exist by default)

#>
Function GetUserPin()
{
	Param($domain,`
		$username`
	)
	add-type -Path "c:\Program Files\Collective Software\AuthLite\CSALnetClient.dll"
	add-type -Path "c:\Program Files\Collective Software\AuthLite\Collective.AuthLite.Common.dll"
	add-type -Path "c:\Program Files\Collective Software\AuthLite\Collective.YubiAuth.dll"
	
	$preq = new-object Collective.AuthLite.Protocol.AuthLiteGetUserPinRequest
	$preq.Domain = $domain
	$preq.Username = $username
	$req = new-object Collective.AuthLite.Protocol.AuthLiteInfrastructureRequest
	$req.Domain = $domain
	$req.GetUserPinRequest = $preq

	try
	{
		$client = new-object Collective.AuthLite.CSALnetClient.Client
		$res = $client.ProcessRequest($req)
		$pres = $res.GetUserPinResponse
		$eres = $res.ErrorMessage

		if($pres -ne $null)
		{
			if($pres.Status -eq [Collective.AuthLite.Protocol.AuthLiteGetUserPinStatus]::Success)
			{
				write-output "GetUserPin Succeeded" # return this first
				write-output ("Length: " + $pres.Length)
				write-output ("Hash: " + $pres.Hash)
			}
			else
			{
				write-output("GetUserPinStatus: " + $pres.Status) # return this first
			}
		}
		elseif($eres -ne $null)
		{
			return $eres
		}
		else
		{
			write-error "Nothing in response"
		}
	}
	catch [Collective.AuthLite.CSALnetClient.LsaOperationException]
	{
		# http://www.vexasoft.com/blogs/powershell/7255220-powershell-tutorial-try-catch-finally-and-error-handling-in-powershell
		$m = $_.Exception.Message
		write-error "LSA exception: $m"
	}
	catch
	{
		$m = $_.Exception.Message
		write-error "exception: $m"
	}
}

<#
.SYNOPSIS 
Sets the specified PIN for this user

.PARAMETER domain 
Use the short (NETBIOS) domain
.PARAMETER username
Use the short (sAMAccountName) username
.PARAMETER pin
A string containing the value to use for this user's PIN
.NOTES
Calling context must be one of:
1) A Domain Admin 
2) The user whose PIN is being set
3) A member of the group specified in Administrative Groups -> Allowed to program and Import AuthLite keys

#>
Function SetUserPin()
{
	Param($domain,`
		$username,`
		$pin`
	)
	add-type -Path "c:\Program Files\Collective Software\AuthLite\CSALnetClient.dll"
	add-type -Path "c:\Program Files\Collective Software\AuthLite\Collective.AuthLite.Common.dll"
	
	$hash = [Collective.Util.AuthUtil]::ComputeUserPinHash([Guid]::NewGuid(), $domain, $username, $pin)

	$preq = new-object Collective.AuthLite.Protocol.AuthLiteSetUserPinRequest
	$preq.Domain = $domain
	$preq.Username = $username
	$preq.Length = $pin.Length
	$preq.Hash = $hash
	$req = new-object Collective.AuthLite.Protocol.AuthLiteInfrastructureRequest
	$req.Domain = $domain
	$req.SetUserPinRequest = $preq

	try
	{
		$client = new-object Collective.AuthLite.CSALnetClient.Client
		$res = $client.ProcessRequest($req)
		$eres = $res.ErrorMessage

		if($eres -ne $null)
		{
			return $eres
		}
		else
		{
			write-output "SetUserPin returned nothing (success)"
		}
	}
	catch [Collective.AuthLite.CSALnetClient.LsaOperationException]
	{
		# http://www.vexasoft.com/blogs/powershell/7255220-powershell-tutorial-try-catch-finally-and-error-handling-in-powershell
		$m = $_.Exception.Message
		write-error "LSA exception: $m"
	}
	catch
	{
		$m = $_.Exception.Message
		write-error "exception: $m"
	}
}


<#
.SYNOPSIS 
Prints a list of OTP tokens assigned to the specified user

.PARAMETER domain 
Use the short (NETBIOS) domain
.PARAMETER username
Use the short (sAMAccountName) username
.PARAMETER types
Restrict to the specified list of AuthLiteTokenType's. 
default= @(YubiKeyOTP, OathTimeSynced, LocalOath, OfflineOath)

.NOTES
Calling context must be one of:
1) A Domain Admin 
2) The user whose tokens are being listed AND a 2-factor authenticated session
3) A member of the group specified in Administrative Groups -> Allowed to program and Import AuthLite keys
#>
Function ListTokens()
{
	Param($domain,`
		$username,`
		$types, `
		$objects)

	add-type -Path "c:\Program Files\Collective Software\AuthLite\CSALnetClient.dll"
	add-type -Path "c:\Program Files\Collective Software\AuthLite\Collective.AuthLite.Common.dll"

	$lreq = new-object Collective.AuthLite.Protocol.AuthLiteListTokensRequest
	if($domain -ne $null) {$lreq.Domain = $domain}
	if($username -ne $null ) {$lreq.Username = $username}
	if($types -ne $null) {$lreq.RestrictToTokenTypes = [Collective.AuthLite.Protocol.AuthLiteTokenType[]] $types}
	$req = new-object Collective.AuthLite.Protocol.AuthLiteInfrastructureRequest
	$req.Domain = $domain
	$req.ListTokensRequest = $lreq

	try
	{
		$client = new-object Collective.AuthLite.CSALnetClient.Client
		$res = $client.ProcessRequest($req)
		$lres = $res.ListTokensResponse
		$eres = $res.ErrorMessage

		if($lres -ne $null)
		{
			write-output ("ListTokens Status: " + $lres.Status)
			write-output ("Tokens found: " + (?: {$lres.Tokens -eq $null} {"0"} {$lres.Tokens.Count}))
			foreach($t in $lres.Tokens)
			{
				write-output $t.ToString()
			}
		}
		elseif($eres -ne $null)
		{
			return $eres
		}
		else
		{
			write-error "Nothing in response"
		}
	}
	catch [Collective.AuthLite.CSALnetClient.LsaOperationException]
	{
		# http://www.vexasoft.com/blogs/powershell/7255220-powershell-tutorial-try-catch-finally-and-error-handling-in-powershell
		$m = $_.Exception.Message
		write-error "LSA exception: $m"
	}
	catch
	{
		$m = $_.Exception.Message
		write-error "exception: $m"
	}
}

<#
.SYNOPSIS 
Disable the OTP token whose ID is specified

.PARAMETER domain 
Use the short (NETBIOS) domain
.PARAMETER username
Use the short (sAMAccountName) username
.PARAMETER id
The ID string of this token, as returned by ListTokens

.NOTES
Calling context must be one of:
1) A Domain Admin 
2) The user whose tokens are being listed AND a 2-factor authenticated session
3) A member of the group specified in Administrative Groups -> Allowed to program and Import AuthLite keys
#>
Function DisableToken()
{
	Param($domain,`
		$username,`
		$id)

	add-type -Path "c:\Program Files\Collective Software\AuthLite\CSALnetClient.dll"
	add-type -Path "c:\Program Files\Collective Software\AuthLite\Collective.AuthLite.Common.dll"

	$dreq = new-object Collective.AuthLite.Protocol.AuthLiteDisableTokenRequest
	if($domain -ne $null) {$dreq.Domain = $domain}
	if($username -ne $null ) {$dreq.Username = $username}
	if($id -ne $null) {$dreq.ID = $id}
	$req = new-object Collective.AuthLite.Protocol.AuthLiteInfrastructureRequest
	$req.Domain = $domain
	$req.DisableTokenRequest = $dreq

	try
	{
		$client = new-object Collective.AuthLite.CSALnetClient.Client
		$res = $client.ProcessRequest($req)
		$dres = $res.DisableTokenResponse
		$eres = $res.ErrorMessage

		if($dres -ne $null)
		{
			write-output ("DisableToken Status: " + $dres.Status)
		}
		elseif($eres -ne $null)
		{
			return $eres
		}
		else
		{
			write-error "Nothing in response"
		}
	}
	catch [Collective.AuthLite.CSALnetClient.LsaOperationException]
	{
		# http://www.vexasoft.com/blogs/powershell/7255220-powershell-tutorial-try-catch-finally-and-error-handling-in-powershell
		$m = $_.Exception.Message
		write-error "LSA exception: $m"
	}
	catch
	{
		$m = $_.Exception.Message
		write-error "exception: $m"
	}
}

<#
.SYNOPSIS 
Tells you whether the specified user is a member of any AuthLite groups

.DESCRIPTION
Returns an enumerated type Collective.AuthLite.Protocol.AuthLiteIsAuthLiteUserStatus whose possible values are:
	No:			Not an AuthLite user.
	YesNA:		The specified $domain\$username is an AuthLite user.
	Yes1FA:		Calling context is an AuthLite user whose session is 1-factor.
	Yes2FA:		Calling context is AuthLite user whose session is 2-factor.

.PARAMETER domain 
Use the short (NETBIOS) domain
.PARAMETER username
Use the short (sAMAccountName) username
.PARAMETER source
"Proto" to look up the specified $domain\$username. "Session" to check the calling user
.PARAMETER cacheok
For "Proto" lookups. Specify "No" to force a fresh lookup, "Yes" (default) to permit a cached answer

.NOTES
Calling context must be one of:
1) A Domain Admin 
2) This computer's account (NetworkService, AppPoolIdentity, etc.)
3) A member of the security group whose SID (without brackets) is stored in the partition setting "CallIAUGroup" (does not exist by default)

.EXAMPLE
IsAuthLiteUser -domain sandbox -user duser1 -source proto -cacheok no
Check whether sandbox\duser1 is a member of any AuthLite Groups

.EXAMPLE
IsAuthLiteUser -source session
Check caller's logon session for presence of AuthLite Groups
#>
Function IsAuthLiteUser()
{
	Param($domain,`
		$username,`
		$source,`
		$cacheok)

	add-type -Path "c:\Program Files\Collective Software\AuthLite\CSALnetClient.dll"
	add-type -Path "c:\Program Files\Collective Software\AuthLite\Collective.AuthLite.Common.dll"

	$areq = new-object Collective.AuthLite.Protocol.AuthLiteIsAuthLiteUserRequest
	if($source -ne $null) {$areq.Source = [Collective.AuthLite.Protocol.AuthLiteCredentialSource] $source}
	else { write-error "Credential source is required for this operation" }
	if($domain -ne $null) {$areq.Domain = $domain}
	if($username -ne $null ) {$areq.Username = $username}
	if($cacheok -ne $null) {$areq.CacheOK = [Collective.AuthLite.Protocol.AuthLiteOKToUseCache] $cacheok}
	$req = new-object Collective.AuthLite.Protocol.AuthLiteInfrastructureRequest
	$req.Domain = $domain
	$req.IsAuthLiteUserRequest = $areq

	try
	{
		$client = new-object Collective.AuthLite.CSALnetClient.Client
		$res = $client.ProcessRequest($req)
		$ares = $res.IsAuthLiteUserResponse
		$eres = $res.ErrorMessage

		if($ares -ne $null)
		{
			write-output ("IsAuthLiteUser Status: " + $ares.Status)
		}
		elseif($eres -ne $null)
		{
			return $eres
		}
		else
		{
			write-error "Nothing in response"
		}
	}
	catch [Collective.AuthLite.CSALnetClient.LsaOperationException]
	{
		# http://www.vexasoft.com/blogs/powershell/7255220-powershell-tutorial-try-catch-finally-and-error-handling-in-powershell
		$m = $_.Exception.Message
		write-error "LSA exception: $m"
	}
	catch
	{
		$m = $_.Exception.Message
		write-error "exception: $m"
	}
}


<#
.SYNOPSIS 
Creates the "User PINS Reader" group if it doesn't exist, and adds a specified computer account to it.

.PARAMETER computername
The NETBIOS name of the computer account

.EXAMPLE
AddUserPinsReader -computername nps

#>
Function AddUserPinsReader()
{
	Param($computername)
		
	import-module ActiveDirectory
	$settingname = "ReadUserPinsGroup"
   $name = "AuthLite UserPin Readers"
	$groupsid = GetPartitionSetting -name $settingname
   if($groupsid -eq $null)
   {
      $domdn = Get-ADDomain | select -ExpandProperty DistinguishedName     
      New-ADGroup -Name $name -SamAccountName $name -GroupCategory Security -GroupScope Global -DisplayName $name -Path "CN=Users,$domdn"
      $groupsid = (get-adgroup -filter {sAMAccountName -eq $name}).SID.Value
      SetPartitionSetting -name $settingname -value $groupsid -reload $true 
   }
	Add-ADGroupMember $name ("$computername" + "$")
	write-output "You must *reboot* ""$computername"" for this permission to take effect." 
}

<#
.SYNOPSIS 
Creates the "User PIN Setters" group if it doesn't exist, and adds a specified computer account to it.

.PARAMETER computername
The NETBIOS name of the computer account

.EXAMPLE
AddUserPinsSetter -computername nps

#>
Function AddUserPinsSetter()
{
	Param($computername)
	import-module ActiveDirectory

	$settingname = "SetUserPinsGroup"
   $name = "AuthLite UserPin Setters"
	$groupsid = GetPartitionSetting -name $settingname
   if($groupsid -eq $null)
   {
      $domdn = Get-ADDomain | select -ExpandProperty DistinguishedName     
      New-ADGroup -Name $name -SamAccountName $name -GroupCategory Security -GroupScope Global -DisplayName $name -Path "CN=Users,$domdn"
      $groupsid = (get-adgroup -filter {sAMAccountName -eq $name}).SID.Value
      SetPartitionSetting -name $settingname -value $groupsid -reload $true 
   }
	Add-ADGroupMember $name ("$computername" + "$")
	write-output "You must *reboot* ""$computername"" for this permission to take effect." 
}

Function ParseSeed($stringSeed)
{
	add-type -Path "c:\Program Files\Collective Software\AuthLite\Collective.YubiAuth.dll"
	add-type -Path "c:\Program Files\Collective Software\AuthLite\Collective.Oath.dll"
	$stringSeed = $stringSeed.Trim()
	try
	{
		$seed = [Collective.YubiAuth.Hex]::Decode($stringSeed)
		return $seed
	}
	catch [System.Exception]
	{
		$Error.Clear()
	}
	try
	{
		$seed = [Collective.Oath.Base32Encoding]::ToBytes($stringSeed)
		return $seed
	}
	catch [System.Exception]
	{
		$Error.Clear()
	}
	try
	{
		$seed = [System.Convert]::FromBase64String($stringSeed)
		return $seed
	}
	catch [System.Exception]
	{
		$Error.Clear()
	}
	return $null
}


Function OathTest
{
   param(
   $username,`
   [datetime]$serverTime,`
   $window,`
   $showRecoveryTokens,`
   $overrideDrift, `
   $token
   )
    
   If (-NOT ([Security.Principal.WindowsPrincipal] `
     [Security.Principal.WindowsIdentity]::GetCurrent()
   ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
   {
     Write-Error "Please re-run this script as a Domain Admin, in a UAC-elevated ('Run as Administrator') powershell prompt"
     Break
   }
   
   if($serverTime -eq $null)
   {
      $serverTime = [DateTime]::Now
   }
   $utc = $serverTime.ToUniversalTime()
   
   if($window -eq $null)
   {
      $window = GetPartitionSetting -name "OathWindow"
   }
   if($window -eq $null)
   {
      $window = 4
   }
   $digits = GetPartitionSetting -name "OathOTPLength"
   if($digits -eq $null)
   {
      $digits = 6
   }
   
   add-type -Path "c:\Program Files\Collective Software\AuthLite\Collective.Oath.dll"
   add-type -Path "c:\Program Files\Collective Software\AuthLite\Collective.AuthLite.Common.dll"
   add-type -Path "c:\Program Files\Collective Software\AuthLite\Collective.YubiAuth.dll"
   import-module ActiveDirectory
   if(-not $?)
   {
      write-error "Please re-run this script on a DC or machine that has AD administrative tools installed"
      break
   }

   $domdn = Get-ADDomain | select -ExpandProperty DistinguishedName            
   $keys = "LDAP://CN=AuthLiteKeys,DC=AuthLite," + $domdn
   
   $searcher = New-Object adsisearcher
   $typefilter = (?: {$showRecoveryTokens -eq $true} {""} {"(|(!(collectiveAuthLiteTokenType=*))(!(collectiveAuthLiteTokenType=5)))"})
   $descfilter = (?: {$token -eq $null} {""} {"(collectiveAuthLiteDescriptiveID=$token)"})
   $userfilter = (?: {$username -eq $null} {""} {"(collectiveAuthLiteUsername=$username)"})
   $searcher.Filter = "(&(collectiveAuthLiteOathSecret=*)$userfilter$descfilter$typefilter)"
   $searcher.SearchRoot = $keys
   $searcher.PageSize = 1000
   $results = $searcher.FindAll()
    
   foreach($result in $results)
   {
       $key = [ADSI]$result.Path
       foreach($item in $key)
       {

	      $algo = "SHA1"
		  if($item.collectiveAuthLiteTokenAlgorithm.Value -ne $null)
		  {
			$algo = [Collective.AuthLite.Protocol.AuthLiteTokenAlgorithm] $item.collectiveAuthLiteTokenAlgorithm.Value
		  }
          $secret = [Collective.YubiAuth.Hex]::Decode($item.collectiveAuthLiteOathSecret.Value)
          $interval = $item.collectiveAuthLiteOathInterval.Value
          if($interval -eq $null)
          {
             $interval = 30
          }
          foreach($delta in (-1*$window)..($window))
          {
			 if($algo -eq "SHA1")
			 {
				$otpgen = new-object Collective.Oath.TOTP(0, $interval, $null)
			 }
			 else
			 {
				$otpgen = new-object Collective.Oath.TOTPSHA256(0, $interval, $null)
			 }
             $drift = [int]($item.collectiveAuthLiteOathDrift.Value)
             $driftprint = $drift
             if($overrideDrift -ne $null)
             {
                  $drift = [int]::Parse($overrideDrift)
             }
             elseif($drift -eq 2147483647)
             {
                  $drift = 0
                  $driftprint = "unknown"
             }
             $deltachar = ""
             if($delta -gt 0)
             {
                  $deltachar = "+"
             }
             elseif($delta -eq 0)
             {
                  $deltachar = "*"
             }
             $driftchar = "+"
             if($drift -lt 0)
             {
                  $driftchar = ""
             }
             $utcd = $utc + (new-timespan -seconds (($drift+$delta) * $interval))
             $props = [ordered]@{}
             if($username -eq $null)
             {
                $props["Username"] = $item.collectiveAuthLiteUsername.Value
             }
             if($token -eq $null)
             {
                $props["Token"] = $item.collectiveAuthLiteDescriptiveID.Value
             }
             $props["Delta"] = "$deltachar$delta($driftchar$driftprint)"
             $props["TokenTime"] = $utcd.ToLocalTime().ToString("t")
			 $dontcare = 0
             $props["OTP"] = $otpgen.GenerateTOTP($secret, $utcd, [ref] $dontcare, $digits)
			 $props["Algorithm"] = $algo
             [pscustomobject]$props
          }
       }
   }
}

Function GetDirectoryContext()
{
    Param($dcName)

    return New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext([System.DirectoryServices.ActiveDirectory.DirectoryContextType]::DirectoryServer, $dcName)
}
Function GetSchemaContext()
{
    $dcName = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Forest.SchemaRoleOwner.Name
    return GetDirectoryContext($dcName)
}

Function AllowProvisionersToDelete()
{
    Param($allow)

	import-module ActiveDirectory

   	[System.Security.Principal.SecurityIdentifier] $sid = New-Object System.Security.Principal.SecurityIdentifier(GetPartitionSetting -name ProvisionersGroup)
	$domdn = Get-ADDomain | select -ExpandProperty DistinguishedName            
	$partitionName = "DC=AuthLite," + $domdn
    [System.DirectoryServices.ActiveDirectory.DirectoryContext]$scontext = GetSchemaContext
    [System.DirectoryServices.ActiveDirectory.ApplicationPartition] $partition = [System.DirectoryServices.ActiveDirectory.ApplicationPartition]::FindByName($scontext, $partitionName)
    $partitionEntry = $partition.GetDirectoryEntry()
    [adsi] $keys = $partitionEntry.Children.Find("CN=AuthLiteKeys")
    [System.DirectoryServices.ActiveDirectory.ActiveDirectorySchema] $schema = [System.DirectoryServices.ActiveDirectory.ActiveDirectorySchema]::GetSchema($scontext)
    [guid] $keyType = $schema.FindClass("collectiveAuthLiteKey").SchemaGuid
    [System.DirectoryServices.ActiveDirectoryAccessRule] $rule = `
        New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, `
        [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild, `
        [System.Security.AccessControl.AccessControlType]::Allow, $keyType)
    if($allow -eq $null -or $allow -eq $true)
    {
        $keys.ObjectSecurity.AddAccessRule($rule)
        Write-Output "Provisioners can now Delete tokens"
    }
    else
    {
        if($keys.ObjectSecurity.RemoveAccessRule($rule))
        {
            Write-Output "Provisioners can no longer Delete tokens"
        }
    }

    $keys.CommitChanges()
}

Function AddTypeCommonDll()
{
	add-type -Path "c:\Program Files\Collective Software\AuthLite\Collective.AuthLite.Common.dll"
}
Function AddTypeConfigDll()
{
	if (-not (test-path "c:\Program Files\Collective Software\AuthLite\AuthLiteConfiguration.dll"))
	{
		write-output "Trying to copy AuthLiteConfiguration.exe to .dll"
		pushd "c:\Program Files\Collective Software\AuthLite\"
		cmd /c mklink AuthLiteConfiguration.dll AuthLiteConfiguration.exe
		popd
	}
	add-type -Path "c:\Program Files\Collective Software\AuthLite\AuthLiteConfiguration.dll"
}

Function UnassignToken()
{
	Param($PublicIdHash)

	AddTypeConfigDll
	AddTypeCommonDll

	$u = new-object AuthLiteConfiguration.DataStoreManager -argumentlist @($null)
	$ds = $u.DataStore
	$k = new-object Collective.AuthLite.DataStore.AuthLiteKey
	$k.PublicId = $PublicIdHash
	$k.Domain = [NullString]::Value
	$k.Username = [NullString]::Value
	$f = New-Object Collective.AuthLite.DataStore.AuthLiteKey+Fields
	$f = [Collective.AuthLite.DataStore.AuthLiteKey+Fields]::Username -bor [Collective.AuthLite.DataStore.AuthLiteKey+Fields]::Domain
	$ds.StoreAuthLiteKey($k.PublicId, $k, $f)
}
Function UnassignTokenBySerial($serial)
{
	import-module ActiveDirectory
	$domdn = Get-ADDomain | select -ExpandProperty DistinguishedName            
	$key = get-adobject -filter {collectiveAuthLiteSerialNumber -eq $serial} -SearchBase ("CN=AuthLiteKeys,dc=AuthLite," + $domdn)
   
	if($key -ne $null)
	{
		if($key -is [system.array])
		{
			foreach($k in $key)
			{
				UnassignToken($k.Name)
			}
		}
		else
		{
			UnassignToken($key.Name)
		}
	}
	else
	{
		write-output "Could not find token: $serial"
	}
}

Function LookupRequest()
{
	Param($otp,`
		$scope,`
		$domain,`
		$username,`
		$types)

	add-type -Path "c:\Program Files\Collective Software\AuthLite\CSALnetClient.dll"
	AddTypeCommonDll

	$lreq = new-object Collective.AuthLite.Protocol.AuthLiteLookupRequest
	if($otp -ne $null) {$lreq.OtpString = $otp}
	if($scope -ne $null) {$lreq.Scope = [Collective.AuthLite.Protocol.AuthLiteLookupScope] $scope}
	if($domain -ne $null) {$lreq.Domain = $domain}
	if($username -ne $null ) {$lreq.Username = $username}
	if($types -ne $null) {$lreq.RestrictToTokenTypes = [Collective.AuthLite.Protocol.AuthLiteTokenType[]] $types}
	$req = new-object Collective.AuthLite.Protocol.AuthLiteInfrastructureRequest
	$req.Domain = $domain
	$req.LookupRequestMessage = $lreq

	try
	{
		$client = new-object Collective.AuthLite.CSALnetClient.Client
		$res = $client.ProcessRequest($req)
		$lres = $res.LookupResponseMessage
		$eres = $res.ErrorMessage

		if($lres -ne $null)
		{
			write-output ("Lookup Status: " + $lres.Status)
			write-output ("Lookup Domain: " + (?: {$lres.Domain -eq $null} {"<null>"} {$lres.Domain}))
			write-output ("Lookup Username: " + (?: {$lres.Username -eq $null} {"<null>"} {$lres.Username}))
			write-output ("Lookup UserType: " + (?: {$lres.UserType -eq $null} {"<null>"} {$lres.UserType}))
			write-output ("Lookup FQDNDomain: " + (?: {$lres.FQDNDomain -eq $null} {"<null>"} {$lres.FQDNDomain}))
		}
		elseif($eres -ne $null)
		{
			return $eres
		}
		else
		{
			write-error "Nothing in response"
		}
	}
	catch [Collective.AuthLite.CSALnetClient.LsaOperationException]
	{
		# http://www.vexasoft.com/blogs/powershell/7255220-powershell-tutorial-try-catch-finally-and-error-handling-in-powershell
		$m = $_.Exception.Message
		write-error "LSA exception: $m"
	}
	catch
	{
		$m = $_.Exception.Message
		write-error "exception: $m"
	}
}

function Get-Token()
{
	param($UsernameLike, $TokenTypes)

	add-type -Path "c:\Program Files\Collective Software\AuthLite\CSALnetClient.dll"
	add-type -Path "c:\Program Files\Collective Software\AuthLite\Collective.AuthLite.Common.dll"
	import-module ActiveDirectory

	$domdn = Get-ADDomain | select -ExpandProperty DistinguishedName            
	$keys = "LDAP://CN=AuthLiteKeys,DC=AuthLite," + $domdn

	$searcher = New-Object adsisearcher
	$searcher.Filter = "(objectClass=collectiveAuthLiteKey)"
	$searcher.SearchRoot = $keys
	$searcher.PageSize = 1000
	$results = $searcher.FindAll()

	foreach($result in $results)
	{
		$key = [ADSI]$result.Path
		foreach($item in $key)
		{
		   try
		   {
		     $usage = "Online"
			  $type = (?: {$item.collectiveAuthLiteTokenType[0] -ne $null } { [Collective.AuthLite.Protocol.AuthLiteTokenType] $item.collectiveAuthLiteTokenType[0] } {"NULL"} )
			  if($item.collectiveAuthLiteChallengeSecret[0] -ne $null)
			  {
			     $usage = "Both"
			  }
			  if($type -eq "OfflineOath" -or $type -eq "RecoveryOath")
			  {
			     $usage = "Offline"
			  }
			  if(($UsernameLike -eq $null -or $item.collectiveAuthLiteUsername[0] -match $UsernameLike) -and `
				 ($TokenTypes -eq $null -or $TokenTypes -contains  $type ))
			  {
				 $cn = $item.cn[0]
				 $user = $item.collectiveAuthLiteDomain.ToString().ToLower() + "\" + $item.collectiveAuthLiteUsername.ToString().ToLower()
				 $serialNumber = $item.collectiveAuthLiteSerialNumber[0]
				 $descriptiveID = $item.collectiveAuthLiteDescriptiveID[0]
				 $lastModified = $item.whenChanged[0]
				 $lastUsed = $item.collectiveAuthLiteCounterUpdateTimeStamp[0]
				 $drift = $item.collectiveAuthLiteOathDrift[0]
          
				 [pscustomobject] @{UID = $cn; User = $user; Type = $type; Usage = $usage; SerialNumber = $serialNumber; DescriptiveID = $descriptiveID; LastModified = $lastModified; LastUsed = $lastUsed; Drift = $drift}
			  }
		   }
		   catch
		   {
			  if($_.Exception.InnerException.GetType() -ne [System.ArgumentException])
			  {
				 write-output $_.Exception
			  }
		   }
		}
	}
}
function Update-TokenType()
{
	[CmdLetBinding(SupportsShouldProcess=$True)]
	param([parameter(ValueFromPipelineByPropertyName)][alias("cn")]$UID, $UIDs, $UsernamesLike, $DescriptiveIDLike, $FromTokenTypes, $ToTokenType, [switch]$Force)

	begin {
		add-type -Path "c:\Program Files\Collective Software\AuthLite\CSALnetClient.dll"
		add-type -Path "c:\Program Files\Collective Software\AuthLite\Collective.AuthLite.Common.dll"
		if($ToTokenType -eq $null) {
		   write-error "Must specify -ToTokenType, i.e. YubiKeyOTP, OathTimeSynced, LocalOath, OfflineOath" 
		   continue #means skip rest
		}
		$ToTokenType = [Collective.AuthLite.Protocol.AuthLiteTokenType] $ToTokenType

		if($UIDs -eq $null) { $UIDs = @() }
	}
	process {
		if($UID -ne $null)
		{
			$UIDs += $UID
		}
	}
	end {	
		import-module ActiveDirectory
		$domdn = Get-ADDomain | select -ExpandProperty DistinguishedName            
		$keys = "LDAP://CN=AuthLiteKeys,DC=AuthLite," + $domdn

		$searcher = New-Object adsisearcher
		$searcher.Filter = "(objectClass=collectiveAuthLiteKey)"
		$searcher.SearchRoot = $keys
		$searcher.PageSize = 1000
		$results = $searcher.FindAll()

		$usualFromTypes = ("NULL", [Collective.AuthLite.Protocol.AuthLiteTokenType]::LocalOath)

		foreach($result in $results)
		{
			$key = [ADSI]$result.Path
			foreach($item in $key)
			{
			   try
			   {
				  $type = $null
				  if($item.collectiveAuthLiteTokenType[0] -ne $null)
				  { 
					$type = [Collective.AuthLite.Protocol.AuthLiteTokenType] $item.collectiveAuthLiteTokenType[0] 
				  } 
				  else
				  {
					$type = "NULL"
				  }
				  if(($UsernamesLike -eq $null -or $item.collectiveAuthLiteUsername[0] -match $UsernamesLike) -and `
					 ($DescriptiveIDLike -eq $null -or $item.collectiveAuthLiteDescriptiveID[0] -match $DescriptiveIDLike) -and `
					 ($FromTokenTypes -eq $null -or $FromTokenTypes -contains  $type ) -and `
					 ($UIDs.Count -eq 0 -or $UIDs -contains $item.cn[0]) -and `
					 ($type -ne $ToTokenType))
				  {
					 $cn = $item.cn[0]
					 $user = $item.collectiveAuthLiteDomain.ToString().ToLower() + "\" + $item.collectiveAuthLiteUsername.ToString().ToLower()
					 $serialNumber = $item.collectiveAuthLiteSerialNumber[0]
					 $descriptiveID = $item.collectiveAuthLiteDescriptiveID[0]
					 $lastModified = $item.whenChanged[0]
					 $lastUsed = $item.collectiveAuthLiteCounterUpdateTimeStamp[0]
					 $oathSecret = $item.collectiveAuthLiteOathSecret[0]
					 [pscustomobject] @{cn = $cn; User = $user; OldType = $type; NewType = $ToTokenType; SerialNumber = $serialNumber; DescriptiveID = $descriptiveID; LastModified = $lastModified; LastUsed = $lastUsed}
             
					 if( $pscmdlet.ShouldProcess($cn, "Update") )
					 {
						if((-not $Force) -and ($ToTokenType.ToString() -match "Oath") -and ($oathSecret -eq $null))
						{
						   write-warning "Token $cn does not seem to be an OATH token, but we have been asked to set it to type $ToTokenType. To do this anyway, use -Force" 
						}
						elseif((-not $Force) -and ($ToTokenType -eq [Collective.AuthLite.Protocol.AuthLiteTokenType]::YubiKeyOTP) -and ($oathSecret -ne $null))
						{
						   write-warning "Token $cn seems to be an OATH token, but we have been asked to set it to type $ToTokenType. To do this anyway, use -Force" 
						}
						elseif((-not $Force) -and (-not ($usualFromTypes -contains $type)))
						{
						   write-warning "Token $cn is type $type which is unusual to want to change. To do this anyway, use -Force"
						}
						else
						{
						   $item.collectiveAuthLiteTokenType = [int]$ToTokenType
						   $item.setinfo()
						}
					 }
				  }
			   }
			   catch
			   {
				  if($_.Exception.InnerException.GetType() -ne [System.ArgumentException])
				  {
					 write-output $_.Exception
				  }
			   }
			}
		}
	}
}

function Reset-TokenDrift()
{
	[CmdLetBinding(SupportsShouldProcess=$True)]
	param([parameter(ValueFromPipelineByPropertyName)][alias("cn")]$UID, $UIDs, $UsernamesLike, $DescriptiveIDLike, $TokenTypes, $ResetTo, [switch]$Force)

	begin {
		add-type -Path "c:\Program Files\Collective Software\AuthLite\CSALnetClient.dll"
		add-type -Path "c:\Program Files\Collective Software\AuthLite\Collective.AuthLite.Common.dll"

		if($UIDs -eq $null) { $UIDs = @() }
	}
	process {
		if($UID -ne $null)
		{
			$UIDs += $UID
		}
	}
	end {	

		import-module ActiveDirectory
		$domdn = Get-ADDomain | select -ExpandProperty DistinguishedName            
		$keys = "LDAP://CN=AuthLiteKeys,DC=AuthLite," + $domdn

		$searcher = New-Object adsisearcher
		$searcher.Filter = "(objectClass=collectiveAuthLiteKey)"
		$searcher.SearchRoot = $keys
		$searcher.PageSize = 1000
		$results = $searcher.FindAll()

		$usualFromTypes = ("NULL", [Collective.AuthLite.Protocol.AuthLiteTokenType]::LocalOath, [Collective.AuthLite.Protocol.AuthLiteTokenType]::OathTimeSynced, [Collective.AuthLite.Protocol.AuthLiteTokenType]::OfflineOath, [Collective.AuthLite.Protocol.AuthLiteTokenType]::RecoveryOath)

		foreach($result in $results)
		{
			$key = [ADSI]$result.Path
			foreach($item in $key)
			{
			   try
			   {
				  $type = $null
				  if($item.collectiveAuthLiteTokenType[0] -ne $null)
				  { 
					$type = [Collective.AuthLite.Protocol.AuthLiteTokenType] $item.collectiveAuthLiteTokenType[0] 
				  } 
				  else
				  {
					$type = "NULL"
				  }
				  if(($UsernamesLike -eq $null -or $item.collectiveAuthLiteUsername[0] -match $UsernamesLike) -and `
					 ($DescriptiveIDLike -eq $null -or $item.collectiveAuthLiteDescriptiveID[0] -match $DescriptiveIDLike) -and `
					 ($TokenTypes -eq $null -or $TokenTypes -contains  $type ) -and `
					 ($UIDs.Count -eq 0 -or $UIDs -contains $item.cn[0]) )
				  {
					 $cn = $item.cn[0]
					 $user = $item.collectiveAuthLiteDomain.ToString().ToLower() + "\" + $item.collectiveAuthLiteUsername.ToString().ToLower()
					 $serialNumber = $item.collectiveAuthLiteSerialNumber[0]
					 $descriptiveID = $item.collectiveAuthLiteDescriptiveID[0]
					 $lastModified = $item.whenChanged[0]
					 $lastUsed = $item.collectiveAuthLiteCounterUpdateTimeStamp[0]
					 $oathSecret = $item.collectiveAuthLiteOathSecret[0]
					 $drift = $item.collectiveAuthLiteOathDrift[0]
					 $newdrift = $ResetTo
					  if($newdrift -eq $null)
					  {
						  if($type -eq "NULL")
						  {
							  write-error "Token $cn is type NULL and you didn't specify a ResetTo, so I'm not sure how to reset it. Try setting the TokenType first with Update-TokenType"
						  }
						  elseif($type -eq [Collective.AuthLite.Protocol.AuthLiteTokenType]::LocalOath)
						  {
							  $newdrift = 2147483647
						  }
						  else
						  {
							  $newdrift = 0
						  }
					  }
					  
					 [pscustomobject] @{cn = $cn; User = $user; Type = $type; SerialNumber = $serialNumber; DescriptiveID = $descriptiveID; LastModified = $lastModified; LastUsed = $lastUsed; OldDrift = $drift; NewDrift = $newdrift}
             
					 if( $pscmdlet.ShouldProcess($cn, "Update") )
					 {
						if((-not $Force) -and (-not ($usualFromTypes -contains $type)))
						{
						   write-warning "Token $cn is type $type which is unusual to want to reset drift. To do this anyway, use -Force"
						}
						else
						{
							$item.collectiveAuthLiteOathDrift = $newdrift
						   $item.setinfo()
						}
					 }
				  }
			   }
			   catch
			   {
				  if($_.Exception.InnerException.GetType() -ne [System.ArgumentException])
				  {
					 write-output $_.Exception
				  }
			   }
			}
		}
	}
}


# —————————————————————————
# Name:   Invoke-Ternary
# Alias:  ?:
# Author: Karl Prosser
# Desc:   Similar to the C# ? : operator e.g.
#            _name = (value != null) ? String.Empty : value;
# Usage:  1..10 | ?: {$_ -gt 5} {"Greater than 5;$_} {"Not greater than 5";$_}
# —————————————————————————
set-alias ?: Invoke-Ternary -Option AllScope -Description "PSCX filter alias"
filter Invoke-Ternary ([scriptblock]$decider, [scriptblock]$ifTrue, [scriptblock]$ifFalse)
{
   if (&$decider) { 
      &$ifTrue
   } else { 
      &$ifFalse 
   }
}


# adapted from http://www.rlmueller.net/PowerShell/PSEnumGroup.txt
# and https://gallery.technet.microsoft.com/scriptcenter/List-Membership-In-bff89703
########################## Function to Generate Domain DN from FQDN ########
Function FQDN2DN
{
	Param ($domainFQDN)
	$colSplit = $domainFQDN.Split(".")
	$FQDNdepth = $colSplit.length
	$DomainDN = ""
	For ($i=0;$i -lt ($FQDNdepth);$i++)
	{
		If ($i -eq ($FQDNdepth - 1)) {$Separator=""}
		else {$Separator=","}
		[string]$DomainDN += "DC=" + $colSplit[$i] + $Separator
	}
	$DomainDN
}
Function GetRootPowerGroupSIDs()
{
	Param($allDomains)
	$colPrivGroups = @()
	$colDomainNames = @()
	$Forest = [System.DirectoryServices.ActiveDirectory.forest]::getcurrentforest()
	$RootDomain = [string]($forest.rootdomain.name)
	
	if($allDomains -ne $true)
	{
		$colDomainNames += [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().ToString()
	}
	else
	{
		$forestDomains = $forest.domains
		ForEach ($domain in $forestDomains)
		{
			$domainname = [string]($domain.name)
			$colDomainNames += $domainname
		}
	}
	$ForestRootDN = FQDN2DN $RootDomain
	$colDomainDNs = @()
	ForEach ($domainname in $colDomainNames)
	{
		$domainDN = FQDN2DN $domainname
		$colDomainDNs += $domainDN	
	}
	$colDASids = @()
	ForEach ($domainDN in $colDomainDNs)
	{
		$adobject = [adsi]"GC://$domainDN"
        $DomainSid = New-Object System.Security.Principal.SecurityIdentifier($AdObject.objectSid[0], 0)
		$DomainSid = $DomainSid.toString()
		$daSid = "$DomainSID-512"
		$colDASids += $daSid
	}

	$GC = $forest.FindGlobalCatalog()
	$adobject = [adsi]"GC://$ForestRootDN"
    $RootDomainSid = New-Object System.Security.Principal.SecurityIdentifier($AdObject.objectSid[0], 0)
	$RootDomainSid = $RootDomainSid.toString()
	#					builtin admins	account oper	server oper		backup oper		Enterprise adm		schema adm
	$colPrivGroups = @("S-1-5-32-544";"S-1-5-32-548";"S-1-5-32-549";"S-1-5-32-551";"$rootDomainSid-519";"$rootDomainSid-518")
	# GORK skip these, DA->Admin, and if there's >1 domain, we don't get built-in admins on other domains from here anyway.
	# $colPrivGroups += $colDASids
    
	return $colPrivGroups

}
Function GetNestedGroupsBySID($SID)
{
	$ADGroup = [adsi]"LDAP://<SID=$SID>"
	GetNestedGroupsHelper $ADGroup @()
}
Function GetNestedGroupsHelper ($ADGroup, $Breadcrumb)
{
	# I'm keeping breadcrumbs as DNs and not group objects because I need a string Contains check to break cycles
	# that means later on they'll have to map DN back to sAMAccountName for printing, instead of just walking the objects.
	$Breadcrumb += ($ADGroup.distinguishedName).ToString()
    ForEach ($MemberDN In $ADGroup.member)
    {
        $MemberDN = $MemberDN.Replace("/", "\/")
		$Member = [ADSI]"LDAP://$MemberDN"
		if($Member.Class -eq "group" -and -not $Breadcrumb.Contains($MemberDN))
		{
			#not the leaf, recurse and add any array returned to our own output
			GetNestedGroupsHelper $Member $Breadcrumb
		}
    }
	# but this group could contain users too, so doing the same action as for a leaf as well
	# return the array we have been building over recursion
	[array]::Reverse($Breadcrumb)
	[pscustomobject] @{
        DN = $Breadcrumb[0]
		Path =  @($Breadcrumb[1..($Breadcrumb.Count-1)])
    }
}

# returns objects of:
# DN: the group Distinguished name
# Path*n*: a path from this group to the root of its power
# (there can be 'n' of these because the graph of memberships could result in more than one route to power)

# the "allDomains" param won't really work, because parts of the script need to look at domain-local stuff, and other parts would need to look at GC stuff,
# and it's just not coded that well yet.
Function GetPrivilegedGroupsWithPaths()
{
	Param($allDomains, $emptyPaths)
	$sids = GetRootPowerGroupSIDs $allDomains
	$GroupPaths = @{}
	#$mostpaths = 0
	$sids | % {
		$GroupObjects = GetNestedGroupsBySID $_
		$GroupObjects | %{
			$go = $_
			if(-not $GroupPaths.ContainsKey($go.DN))
			{
				$GroupPaths[$go.DN] = @()
			}
			if(-not ($GroupPaths[$go.DN]).Contains(@($go.Path)))
			{
				$GroupPaths[$go.DN] += ,@($go.Path)#construct new array as a member, don't collapse elements into parent array

			}
		}
	}
	$GroupPaths.Keys | % {
		[pscustomobject] @{
			"DN" = $_
			"Name" = ([adsi] "LDAP://$_").Properties.Item("sAMAccountName").Value
			"Paths" = @($GroupPaths[$_])
		}
	}
}

Function GetDirectMembersOfGroup($ADGroup)
{
    # Retrieve objectSID of group.
    $oSID = $ADGroup.Properties["objectSid"]

    # Calculate RID, which will be primaryGroupToken of the group,
    # from the last 4 bytes of objectSID.
    $arrSID = ($oSID.ToString()).Split()
    $k = $arrSID.Count
    $RID = [Int32]$arrSID[$k - 4] `
        + (256 * [int32]$arrSID[$k - 3]) `
        + (256 * 256 * [Int32]$arrSID[$k - 2]) `
        + (256 * 256 * 256 * [Int32]$arrSID[$k - 1])

    # Search for objects whose primaryGroupID matches the
    # group primaryGroupToken.
	$D = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
	$Domain = [ADSI]"LDAP://$D"
	$Searcher = New-Object System.DirectoryServices.DirectorySearcher
	$Searcher.PageSize = 200
	$Searcher.SearchScope = "subtree"
	$Searcher.PropertiesToLoad.Add("distinguishedName") > $Null
	$Searcher.PropertiesToLoad.Add("sAMAccountName") > $Null
	$Searcher.PropertiesToLoad.Add("userAccountControl") > $Null
	$Searcher.SearchRoot = "LDAP://" + $Domain.distinguishedName

    $Searcher.Filter = "(primaryGroupID=$RID)"
    $Results = $Searcher.FindAll()
    ForEach ($Result In $Results)
    {
		$disabled = $false
		$uac=$Result.Properties.item("useraccountcontrol")
        $uac=$uac.item(0)
        if (($uac -bor 0x0002) -eq $uac) {$disabled=$true}
		[pscustomobject] @{
			Username = $Result.Properties.Item("sAMAccountName")
			Disabled = $disabled
		}
    }
	
    ForEach ($MemberDN In $ADGroup.member)
    {
        $MemberDN = $MemberDN.Replace("/", "\/")
		$Member = [ADSI]"LDAP://$MemberDN"
		if($Member.Class -eq "user")
		{
			$disabled = $false
			$uac=$Member.Properties.item("useraccountcontrol")
            $uac=$uac.item(0)
            if (($uac -bor 0x0002) -eq $uac) {$disabled=$true}
			[pscustomobject] @{
				Username = $Member.Properties.Item("sAMAccountName").Value
				Disabled = $disabled
			}
		}
    }
}
Function GetDirectMembersOfGroupByDN($dn)
{
	GetDirectMembersOfGroup([adsi] "LDAP://$dn")
}

Function RecordMembership($usersHash, $username, $group)
{
	if(-not $usersHash.ContainsKey($username))
	{
		$usersHash[$username] = @();
	}
	if(-not $usersHash[$username].Contains($group))
	{
		$usersHash[$username] += $group
	}
}
Function GetUsersInGroups()
{
	param($groups)

	$omap = @{}
	$usersHash = @{}
	$umap = @{}
	$groups | % {
		$group = $_
		$omap[$_.Name] = $group
		$users = GetDirectMembersOfGroupByDN $group.DN
		$users | % {
			RecordMembership $usersHash $_.Username $group.Name
			$umap[$_.Username] = $_
		}
	}

	$usersHash.Keys | % {
		$user = $_
		$groupSANs = $usersHash[$user] | Sort-Object
		
		$groupSANs | %{
			[pscustomobject] @{
				Username=$user
				Disabled=$umap[$user].Disabled
				Groupname = $_
				GroupObject = $omap[$_]
			}
		}
	}
}


function Write-ColorOutput($ForegroundColor, $BackgroundColor)
{
    # save the current color
    $fc = [Console]::ForegroundColor
    $bc = [Console]::BackgroundColor

    # set the new color
    [Console]::ForegroundColor = $ForegroundColor
	if($BackgroundColor) {
		[Console]::BackgroundColor = $BackgroundColor
	}

    # output
    if ($args) {
        Write-Output $args
    }
    else {
        $input | Write-Output
    }

    # restore the original color
    [Console]::ForegroundColor = $fc
	if($BackgroundColor) {
		[Console]::BackgroundColor = $bc
	}
}
Function H1($s)
{
	write-output ""
	Write-ColorOutput darkred gray $s
	Write-Output ($s -replace ".","=")
	Write-Output ""
}
Function H2($s)
{
	Write-ColorOutput yellow darkblue $s
	Write-Output ($s -replace ".","-")
}

# using code from https://stackoverflow.com/questions/4647756/is-there-a-way-to-specify-a-font-color-when-using-write-output to keep write-output yet have colors if it's a console host
Function PrintUsersInPowerGroups()
{
	$service = "Any compromise of a system running a service with this account can take over your whole domain! Run as a lower privilege user if possible. Restrict allowed logon types and locations using group policy User Rights Assignment."
	$easa = "AuthLite cannot control membership in Enterprise and Schema admins since they are Universal groups. Remove users (except built-in Administrator) from these groups, and add temporarily when needed for tasks."
	$old = "This group is an old holdover from Server 2000. Remove members and make them OU admins as needed."
	$advice = @{
		"Domain Admins"="For humans: Remove account from this group, add to AuthLite DA and log in with 2-factor auth.`nFor service accounts: $service"
		"Administrators"="Except for the built-in Administrator account, no users should be directly in this group!`nPut humans in AuthLite DA.`nFor service accounts: $service"
		"Enterprise Admins" = $easa
		"Schema Admins" = $easa
		"Account Operators" = $old
		"Backup Operators" = $old
		"Server Operators" = $old
	}
	#property renaming https://technet.microsoft.com/en-us/library/ff394367.aspx
	$groups = GetPrivilegedGroupsWithPaths
	$sanmap = @{}
	$dnmap = @{}
	$groups | % {
		$sanmap[$_.Name] = $_
		$dnmap[$_.DN] = $_
	}

	$utitle = "Users in this group" #since this property name prints out
	
	$currentGroup = $null
	GetUsersInGroups $groups | Sort-Object -Property @("Groupname", "Username") | %{
		$item = $_
		if($currentGroup -ne $item.Groupname)
		{
			Write-Output ""
			write-output ""
			$currentGroup = $item.Groupname
			H1 $item.Groupname
			$adv = "$($advice[$item.Groupname])`n"
			if($adv -eq "`n")
			{
				$adv = "This group is a member of:`n"
				# "Paths" is a list of lists
				$sanmap[$item.Groupname].Paths | % {
					$adv += "{ """
					$sans = @($_ | %{$dnmap[$_].Name})
					$adv +=  $sans -join """ -> """
					$adv += """ }:`n"
					$adv += $advice[$sans[-1]]
					$adv += "`n`n"
				}
			}
			H2 "Advice"
			write-output (word-wrap $adv) #includes its own newlines

			H2 "Users in this group"
		}
		write-output "$($item.Username) $(?: {$item.Disabled} {'(Disabled: delete this user?)'} {''})"
	}
}

#modified from https://stackoverflow.com/questions/1059663/is-there-a-way-to-wordwrap-results-of-a-powershell-cmdlet/1059686
<#
.SYNOPSIS
wraps a string or an array of strings at the console width without breaking within a word
.PARAMETER chunk
a string or an array of strings
.EXAMPLE
word-wrap -chunk $string
.EXAMPLE
$string | word-wrap
#>
function word-wrap {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=1,ValueFromPipeline=1,ValueFromPipelineByPropertyName=1)]
        [Object[]]$chunk
    )
    PROCESS {
        $Lines = @()
        foreach ($oline in $chunk) {
			#preserve inserted newlines
			foreach($line in ($oline -split "`n")) {
				$str = ''
				$counter = 0
				$line -split '\s+' | %{
					$counter += $_.Length + 1
					if ($counter -gt $Host.UI.RawUI.BufferSize.Width) {
						$Lines += ,$str.trim()
						$str = ''
						$counter = $_.Length + 1
					}
					$str = "$str$_ "
				}
				$Lines +=,$str.trim()
			}
        }
        $Lines
    }
}


function Check-Oath-Collisions 
{
	Param([int] $digits = 6)
	$computers = get-adcomputer -filter * | select -expand sAMAccountName | select-string -pattern ('-\d{' + $digits + '}\$$')
    $users = get-aduser -filter * | select -expand sAMAccountName | select-string -pattern ('-\d{' + $digits + '}$')
	if($computers -ne $null)
	{
		Write-Warning "Colliding computer names found:"
		$computers
	}
	if($users -ne $null)
	{
		Write-Warning "Colliding users found:"
		$users
	}
	if($computers -eq $null -and $users -eq $null)
	{
		Write-Output "No conflicts found."
	}

}

function Set-Oath-Digits
{
	Param($reload)
	$conflicts = Check-Oath-Collisions
	if($conflicts -eq "No conflicts found.")
	{
		SetPartitionSetting -name "OathOTPLength" -value "6" -reload $reload
	}
	else
	{
		write-output $conflicts
	}
}

function AUSetAcl($name, $identity, $type)
{
	$augdn = (get-adgroup -filter {(cn -eq $name)}).DistinguishedName
	$aug = [adsi]("LDAP://127.0.0.1/{0}" -f $augdn)
	$adRights = [System.DirectoryServices.ActiveDirectoryRights] "GenericWrite"
	$inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
	$ace = new-object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$adRights,$type,$inheritanceType     
	$aug.ObjectSecurity.AddAccessRule($ace)
	$aug.CommitChanges()    
}

function Create-AuthLite-Groups 
{
	Param($reload)

	Import-Module ActiveDirectory

	$dn = Get-ADDomain | select -ExpandProperty DistinguishedName        

	New-ADGroup -Name "AuthLite 1F Tag" -SamAccountName "AuthLite 1F Tag" -GroupCategory Security -GroupScope Global -DisplayName "AuthLite 1F Tag" -Path "CN=Users,$dn" -Description "Membership is dynamically assigned; do not add users"
	New-ADGroup -Name "AuthLite 2F Tag" -SamAccountName "AuthLite 2F Tag" -GroupCategory Security -GroupScope Global -DisplayName "AuthLite 2F Tag" -Path "CN=Users,$dn" -Description "Membership is dynamically assigned; do not add users"
	New-ADGroup -Name "AuthLite Users" -SamAccountName "AuthLite Users" -GroupCategory Security -GroupScope Global -DisplayName "AuthLite Users" -Path "CN=Users,$dn" -Description "Users in this group will participate in the 2-factor enforcements you put in place"
	New-ADGroup -Name "AuthLite DA" -SamAccountName "AuthLite DA" -GroupCategory Security -GroupScope Global -DisplayName "AuthLite DA" -Path "CN=Users,$dn" -Description "Users in this group will get Domain Admin rights in 2-factor sessions"
	Add-ADGroupMember "AuthLite 1F Tag" "AuthLite Users"

	$identity = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::NetworkServiceSid, $null)
	$type = [System.Security.AccessControl.AccessControlType] "Allow"
	AUSetAcl "AuthLite Users" $identity $type

	$me = [System.Security.Principal.WindowsIdentity]::GetCurrent()
	$identity = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::AccountDomainAdminsSid, $me.User.AccountDomainSid)
	$type = [System.Security.AccessControl.AccessControlType] "Deny"
	AUSetAcl "AuthLite 1F Tag" $identity $type
	AUSetAcl "AuthLite 2F Tag" $identity $type

	if( (FindPartitionSetting | where-object{$_.Name -like 'SessionTag*'}).Count -eq 0)
	{
		SetGroupPairSetting "SessionTagSid_0" "AuthLite 1F Tag" "AuthLite 2F Tag" $false
		SetGroupPairSetting "SessionTagSid_1" "AuthLite DA" "Domain Admins" $false

		AddTypeConfigDll
		$allow = new-object Collections.Generic.List[IdentityResolver]
		$allow.Add( (New-Object IdentityResolver -ArgumentList (New-Object System.Security.Principal.SecurityIdentifier -ArgumentList ([System.security.principal.wellknownsidtype]::WorldSid,$null)) ))
		$deny = new-object Collections.Generic.List[IdentityResolver]
		$deny.Add((New-Object IdentityResolver -ArgumentList (New-Object System.Security.Principal.NTAccount -ArgumentList "AuthLite 1F Tag")))
		$deny.Add((New-Object IdentityResolver -ArgumentList (New-Object System.Security.Principal.NTAccount -ArgumentList "AuthLite 2F Tag")))
		$deny.Add(( New-Object IdentityResolver -ArgumentList (New-Object System.Security.Principal.NTAccount -ArgumentList "AuthLite DA")))
		$deny.Add((New-Object IdentityResolver -ArgumentList (New-Object System.Security.Principal.NTAccount -ArgumentList "Domain Admins")))
		SetPartitionSetting -name "NonAuthLiteUsers" -value (	[AuthLiteConfiguration.Utils]::BuildSDDLFromICollections($allow, $deny)) -reload $false
		SetGroupSetting -name "BootstrapGroup" -group "AuthLite Users"
	}
	if($reload)
	{
		ReloadSettings
	}
}

Function AddReplayWindow()
{
	Param($name,`
		$seconds,`
		$initiate,`
		$full,`
		$initiateSymbolic,`
		$fullSymbolic,`
		$reload,`
		$initiatorSeconds, `
		$overlapped)

	AddTypeConfigDll
	add-type -Path "c:\Program Files\Collective Software\AuthLite\Collective.AuthLite.Common.dll"
	$iirl = new-object Collections.Generic.List[Collective.Util.IPAddressRange]
	if($initiate -ne $null) 
	{
		foreach($init in @($initiate))
		{
			$iirl.Add($init)
		}
	}
	$sirl = new-object Collections.Generic.List[Collective.Util.IPAddressRange]
	if($full -ne $null) 
	{
		foreach($f in @($full))
		{
			$sirl.Add($f)
		}
	}
	[AuthLiteConfiguration.ReplayWindow]$w = new-object AuthLiteConfiguration.ReplayWindow
	$w.name = $name
	$w.duration = $seconds
	$w.ipRangesInitiator = $iirl
	$w.ipRangesPermission = $sirl
	if($initiateSymbolic -ne $null) { $w.sddlInitiators = $initiateSymbolic }
	if($fullSymbolic -ne $null) { $w.sddlPermissions = $fullSymbolic }
	if($initiatorSeconds -ne $null) {$w.initiatorDuration = $initiatorSeconds }
	if($overlapped -ne $null) {$w.overlapped = $overlapped }
	
	# when it's an empty list, it gets forced to null. if i @(GetReplayWindows) then:
	# for some reason this works from command line, but is of the wrong type (system.object[]) from nunit
	# so.. do this:
	
	#[Collections.Generic.List[AuthLiteConfiguration.ReplayWindow]]$windows = GetReplayWindows
	$windows = new-object Collections.Generic.List[AuthLiteConfiguration.ReplayWindow] 
	$dumbwindows = @(GetReplayWindows)
	foreach($dw in $dumbwindows)
	{
		$windows.Add($dw)
	}
	$windows.Add($w)
	StoreReplayWindows -windows $windows -reload $false
	if($reload -eq $true)
	{
		ReloadSettings
	}

}
Function GetReplayWindows()
{
	AddTypeConfigDll
	$u = new-object AuthLiteConfiguration.DataStoreManager -argumentlist @($null)
	[Collections.Generic.List[AuthLiteConfiguration.ReplayWindow]] $windows = $u.GetReplayWindows()
	return $windows
}
Function StoreReplayWindows()
{
	Param([Collections.Generic.List[AuthLiteConfiguration.ReplayWindow]]$windows,`
	$reload)

	AddTypeConfigDll
	$u = new-object AuthLiteConfiguration.DataStoreManager -argumentlist @($null)

	# when it's an empty list, it gets forced to null. if i @() it then:
	# for some reason this works from command line, but is of the wrong type (system.object[]) from nunit
	# so.. do this:
	if($windows -eq $null)
	{
		[Collections.Generic.List[AuthLiteConfiguration.ReplayWindow]]$windows = new-object Collections.Generic.List[AuthLiteConfiguration.ReplayWindow] 
	}
	$u.StoreReplayWindows($windows)
	if($reload -eq $true)
	{
		ReloadSettings
	}
}
Function NetMaskToCIDR {
  [CmdletBinding()]
  Param(
    [String]$SubnetMask='255.255.255.0'
  )
  $byteRegex='^(0|128|192|224|240|248|252|254|255)$'
  $invalidMaskMsg="Invalid SubnetMask specified [$SubnetMask]"
  Try{
    $netMaskIP=[IPAddress]$SubnetMask
    $addressBytes=$netMaskIP.GetAddressBytes()

    $strBuilder=New-Object -TypeName Text.StringBuilder

    $lastByte=255
    foreach($byte in $addressBytes){

      # Validate byte matches net mask value
      if($byte -notmatch $byteRegex){
        Write-Error -Message $invalidMaskMsg `
          -Category InvalidArgument `
          -ErrorAction Stop
      }elseif($lastByte -ne 255 -and $byte -gt 0){
        Write-Error -Message $invalidMaskMsg `
          -Category InvalidArgument `
          -ErrorAction Stop
      }

      [void]$strBuilder.Append([Convert]::ToString($byte,2))
      $lastByte=$byte
    }

    ($strBuilder.ToString().TrimEnd('0')).Length
  }Catch{
    Write-Error -Exception $_.Exception `
      -Category $_.CategoryInfo.Category
  }
}
function Create-RDP-Replay-Window
{
	AddTypeCommonDll
	$loopback = [ipaddress]::Parse("127.0.0.1")
	$loopbackRange = New-Object Collective.Util.IPAddressRange -ArgumentList $loopback,$loopback

	$nic_configuration = gwmi -computer .  -class "win32_networkadapterconfiguration" | Where-Object {$_.defaultIPGateway -ne $null}
	$ips = $nic_configuration.IPAddress
	$masks = $nic_configuration.IPSubnet
	$ranges = for($i = 0; $i -lt $ips.Count; $i++)
	{
		New-Object Collective.Util.IPAddressRange -ArgumentList ([ipaddress]::Parse($ips[$i])), (?: {$masks[$i] -match "\."} {NetMaskToCIDR $masks[$i]} {128 - $masks[$i]})
	}
	#uniquify
	$uranges = @()
	$urangecheck = @{}
	foreach($range in $ranges)
	{
		if(-not $urangecheck[$range.ToString()])
		{
			$uranges += $range
			$urangecheck[$range.ToString()] = $true
		}
	}
	AddReplayWindow -name "RDP" -seconds "20" -full ($loopbackRange) -initiate $uranges
}

function Check-DC-Replicas
{
	import-module ActiveDirectory
   if(-not $?)
   {
      write-error "Please re-run this script on a DC or machine that has AD administrative tools installed"
      break
   }
   If (-NOT ([Security.Principal.WindowsPrincipal] `
     [Security.Principal.WindowsIdentity]::GetCurrent()
   ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
   {
     Write-Error "Please re-run this script as a Domain Admin, in a UAC-elevated ('Run as Administrator') powershell prompt"
     Break
   }
   
	$domdn = Get-ADDomain | select -ExpandProperty DistinguishedName    
	$fqdn = Get-ADDomain | select -ExpandProperty DNSRoot
	$f = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
	foreach($partition in $f.ApplicationPartitions)
	{
		if($partition.Name -match "DC=AuthLite,$domdn")
		{
			$installed = @{}
			foreach($server in $partition.DirectoryServers)
			{
				$installed[$server.name] = $true
			}
			break
		}
	}
	foreach($site in $f.sites)
	{
		foreach($server in $site.Servers)
		{
			$servername = $server.name #that's all we can do without connecting
			if($servername -like "*$fqdn") #skip other domains in forest
			{
				$authlite = $installed[$servername]
				[pscustomobject] @{
					Site = $site.Name
					Name = $servername;
					PartitionInstalled = $authlite;
				}
			
				#Write-ColorOutput (?: {$authlite} {"Green"} {"Red"}) Black "$server"
			}
		}
	}
}

function Get-Group-Policy-Denies
{
	pushd "$env:SYSTEMROOT\SYSVOL\domain\Policies"
	try
	{
    	Import-Module ActiveDirectory
        # (could also enumerate CN=System,$domain to get policy guids, but still would need to walk the infs to read the settings anyway so...)
		$guids = @{}
		get-childitem -path . -recurse *.inf | 
			select-string -pattern "SeDeny" | 
			%{select-string -InputObject $_.Path -pattern "(?<={)(.*?)(?=})"} | 
			%{$_.Matches} | %{$_.Value} | %{$guids[$_.ToLower()] = $true}

		$gpos = @{}
		get-gpo -all | %{
			$gpo = $_
			if($guids[$gpo.Id.ToString().ToLower()] -and $gpo.GpoStatus -ne "AllSettingsDisabled" -and $gpo.GpoStatus -ne "ComputerSettingsDisabled")
			{
				$gpos[$_.Id.ToString().ToLower()] = $gpo
			}
		}
        # it would be cool to fully build a tree of OUs and where each item is applied or not. but it would be hard, and hard to visualize here
        # probably 90% good enough to just show where they are linked and whether there are any inheritance blocks
        $domain = Get-ADDomain
        $targets = $domain.DistinguishedName, (get-adorganizationalunit -Filter * | Select-Object -ExpandProperty DistinguishedName)
        $targets | %{ 
            $ou = $_
            (get-gpinheritance -target $ou).GpoLinks | %{
                $link = $_
                if($link.Enabled -and $guids[$link.GpoId.ToString().ToLower()])
                {
                    [pscustomobject] @{
                        OU=$ou;
                        Policy=$link.DisplayName;
                    }
                }
            }
        }
	}
	catch
	{
	}
	finally
	{
		popd
	}
}
function Get-Group-Policy-Deny-XML
{
    param(
    $group = "AuthLite 1F Tag",
    [bool] $showAllOUs = $false
    )
   	Import-Module ActiveDirectory

    $alsid = (get-adgroup -identity $group).sid.value

    $rights = @{
        SeDenyNetworkLogonRight = "Network Access";
        SeDenyBatchLogonRight = "Batch Logon";
        SeDenyServiceLogonRight = "Service Logon";
        SeDenyInteractiveLogonRight = "Interactive Logon";
        SeDenyRemoteInteractiveLogonRight = "Remote Desktop Logon";
    }
    [xml]$report = get-gporeport -reporttype xml -all
    $gpos = $report.GPOS
    $nsm = new-object System.Xml.XmlNamespaceManager -ArgumentList $report.NameTable
    $nsm.AddNamespace("xsd", "http://www.w3.org/2001/XMLSchema")
    $nsm.AddNamespace("xsi", "http://www.w3.org/2001/XMLSchema-instance")
    $nsm.AddNamespace("settings", "http://www.microsoft.com/GroupPolicy/Settings")
    $nsm.AddNamespace("security", "http://www.microsoft.com/GroupPolicy/Settings/Security") #q1
    $nsm.AddNamespace("types", "http://www.microsoft.com/GroupPolicy/Types")

    $algpos = @{}
    $nalgpos = @{}

    $gpos.GPO | %{
        $guid = $_.SelectSingleNode("settings:Identifier/types:Identifier/text()", $nsm).Value.ToLower()
        $_.Computer | %{
            if($_.Enabled)
            {
                $denies = $_.SelectNodes("settings:ExtensionData[settings:Name='Security']/settings:Extension/security:UserRightsAssignment[starts-with(security:Name, 'SeDeny')]", $nsm)
                if($denies.Count -gt 0)
                {
                    $al = $false
                    $which = ($denies | %{
                        # save this into the "which" list
                        $rights[$_.SelectSingleNode("security:Name/text()", $nsm).Value]
                        # and see if the policy is ours or not
                        $sid = $_.SelectSingleNode("security:Member/types:SID/text()", $nsm).Value
                        if($sid -eq $alsid)
                        {
                            $al = $true        
                        }
                    })
                    if($al)
                    {
                        $algpos[$guid] = $which
                    }
                    else
                    {
                        $nalgpos[$guid] = $which
                    }
                }
            }
        }
    }
    
    $domdn = Get-ADDomain | select -ExpandProperty DistinguishedName 
    $searcher = new-object adsisearcher
    $searcher.Filter = "(objectClass=organizationalUnit)"
    $searcher.PropertiesToLoad.Add("distinguishedName") | out-null
    $searcher.SearchScope = "Onelevel"
    $searcher.PageSize = 1000
    
    [xml]$out = new-object System.Xml.XmlDocument
    $out.AppendChild( $out.CreateXmlDeclaration("1.0","UTF-8",$null)) | out-null
    $root = $out.AppendChild( $out.CreateElement("root"))
    
    function Recurse
    {
        param([string]$dn, [System.Xml.XmlNode]$parentNode, [string]$parentState)
        $state = "No Enforcement"

        $relevantGpos = (get-gpinheritance -target $dn).InheritedGpoLinks | %{
            $link = $_
            $id = "{$($link.GpoId.ToString().ToLower())}"
            if($link.Enabled)
            {
                if($algpos[$id])
                {
                    #output it to the gpos list
                    $link.DisplayName
                    if($state -eq "No Enforcement") {$state = "AuthLite 2F"}
                    elseif($state -eq "Other Policy") {$state = "Other Policy Clobbers AuthLite Policy"}
                }
                elseif($nalgpos[$id])
                {
                    #output it to the gpos list
                    $link.DisplayName
                    if($state -eq "No Enforcement") {$state = "Other Policy"}
                    elseif($state -eq "AuthLite 2F") {$state = "AuthLite Policy Clobbers Other Policy"}
                }
            }
        }
        if($showAllOUs -or $state -ne $parentState)
        {
            $ou = $out.CreateElement("OU")
            $name = $out.CreateAttribute("Name")
            $name.Value = $dn
            $ou.Attributes.Append($name) | Out-Null
            $st = $out.CreateAttribute("State")
            $st.Value = $state
            $ou.Attributes.Append($st) | out-null
            if($relevantGpos.Length -gt 0)
            {
                $policies = $out.CreateElement("Policies")
                $relevantGpos | %{
                    $policy = $out.CreateElement("Policy")
                    $name = $out.CreateAttribute("Name")
                    $name.Value = $_
                    $policy.Attributes.Append($name) | Out-Null
                    $policies.AppendChild($policy) | out-null
                }
                $ou.AppendChild($policies) | Out-Null
            }
            $parentNode.AppendChild($ou) | out-null
            $parentNode = $ou
        }

        $searcher.SearchRoot = "LDAP://$dn"
        $ous = $searcher.FindAll()
        $ous | %{
            Recurse -dn $_.Properties["distinguishedName"][0] -parentNode $parentNode -parentState $state
        }
    }
    Recurse -dn $domdn -parentNode $root -parentState "Root"
    Format-XML $out
}
set-alias -name Check-Group-Policy -Value Get-Group-Policy-Deny-XML

function Format-XML ([xml]$xml, $indent=2)
{
    $StringWriter = New-Object System.IO.StringWriter
    $XmlWriter = New-Object System.XMl.XmlTextWriter $StringWriter
    $xmlWriter.Formatting = "indented"
    $xmlWriter.Indentation = $Indent
    $xml.WriteContentTo($XmlWriter)
    $XmlWriter.Flush()
    $StringWriter.Flush()
    return $StringWriter.ToString()
}
function Get-OUs-Missing-Group-Policy
{
    param(
       $group = "AuthLite 1F Tag"
    )
    [xml]$out = Get-Group-Policy-Deny-XML -group $group -showallous $true
    select-xml -xml $out -xpath "//OU[@State!='AuthLite 2F']" | %{
       [pscustomobject] @{
          OU=$_.Node.Name;
          Problem=$_.Node.State
       }
    }
}

function Create-Group-Policy
{
	$dirname = "GroupPolicy_generic"
	if(-not (Test-Path $dirname -PathType Container))
	{
		if(-not (test-path "$dirname.zip"))
		{
			$url = "http://s3.authlite.com/downloads/2.3/$dirname.zip"
			write-output "Attempt to download: $url"
			try
			{
				Invoke-WebRequest $url -OutFile "$dirname.zip"
			}
			catch
			{
				write-error "Could not get '$url', please download to '$(resolve-path .)' and run this function again."
				return
			}
		}
		try
		{
			Expand-Archive -Path "$dirname.zip"
		}
		catch
		{
			write-error "'$dirname.zip' exists in folder '$(resolve-path .)' but could not unzip. Please extract manually and run this function again."
			return
		}
	}
	else
	{
		write-output "Group policy folder exists..."
	}
	Write-Output "Localize policy contents"
	$policyid = "4DF2ED36-76C2-425D-9126-27EA68603106"
	$policyidg = "{$policyid}"
	pushd $dirname
	pushd $policyidg
	import-module ActiveDirectory
	$domain = Get-ADDomain
	$dn = $domain.DistinguishedName
	$oneftsid = (get-adgroup -filter {sAmAccountName -eq "AuthLite 1F Tag"}).SID.Value

	$domainrid = ($oneftsid -split "-[^-]+$")[0]
	$oneftagid = $rid = ($oneftsid -split "-")[-1]
	$domainfqdn = $domain.DNSRoot
	$domainnbdn = $domain.NetBIOSName
	(Get-Content Backup.xml) | Foreach-Object {
		$_ -replace '#DOMAINFQDN#', $domainfqdn `
		-replace '#DOMAINNBDN#', $domainnbdn `
		-replace '#DOMAINRID#', $domainrid `
		-replace '#1FTAGID#', $oneftagid
	} | Out-File Backup.xml -Encoding UTF8
	(Get-Content gpreport.xml) | Foreach-Object {
		$_ -replace '#DOMAINFQDN#', $domainfqdn `
		-replace '#DOMAINNBDN#', $domainnbdn `
		-replace '#DOMAINRID#', $domainrid `
		-replace '#1FTAGID#', $oneftagid
	} | Out-File gpreport.xml -Encoding UTF8	
	pushd '.\DomainSysvol\GPO\Machine\microsoft\windows nt\secedit'
	(Get-Content GptTmpl.inf) | Foreach-Object {
		$_ -replace '#DOMAINRID#',$domainrid `
		-replace '#1FTAGID#',$oneftagid
	} | Out-File GptTmpl.inf -Encoding Unicode
	popd
	popd
	popd
	Write-Output "Creating policy and importing settings"
	$name = "Computer: Block 1-factor logon by AuthLite Users"
	New-GPO -Name $name | out-null 
	set-gppermissions -name $name -replace -permissionlevel GpoRead -targetname "Authenticated Users" -targettype group | out-null
	set-gppermissions -name $name -permissionlevel GpoApply -TargetName "Authenticated Users" -TargetType group | out-null

	Import-GPO -BackupID $policyidg -TargetName $name -path (Resolve-Path $dirname).Path | out-null
	write-output "Linking group policy to root"
	new-gplink -name $name -target $dn | out-null 
	Write-Warning "Go manually examine group policy on a DC, member server, and workstation, and make exceptions"
}

function Do-Default-Setup
{
	Write-Output "Check-DC-Replicas:"
	Check-DC-Replicas
	Write-Output "Create-AuthLite-Groups:"
	Create-AuthLite-Groups
	Write-Output "Set-Oath-Digits:"
	Set-Oath-Digits
	Write-Output "Create-RDP-Replay-Window:"
	Create-RDP-Replay-Window
    Write-output "Get-Group-Policy-Denies:"
    Get-Group-Policy-Denies
    Write-Output "Check-Group-Policy:"
    Check-Group-Policy

	write-output "Create-Group-Policy"
	Create-Group-Policy
}
Set-Alias -Name Default-Setup -Value Do-Default-Setup
Set-Alias -Name Setup-Defaults -Value Do-Default-Setup
Set-Alias -Name Set-Defaults -Value Do-Default-Setup

function Ping-TCP
{
	Param($ComputerName,
	$Port=3389)
	do
	{
		Start-Sleep -Seconds 3
	} until(Test-NetConnection -Computername $ComputerName -Port $Port -InformationLevel Quiet)
	Write-ColorOutput Green Black "$ComputerName port $Port is open."
}

Set-Alias -Name Test-RDP -Value Ping-TCP
Set-Alias -Name Test-TCP -Value Ping-TCP
Set-Alias -Name Ping-RDP -Value Ping-TCP		

function Invoke-Foreach-Computer
{
	Param(
    [parameter(ValueFromPipeline=1)][Microsoft.ActiveDirectory.Management.ADComputer[]] $InputObject,
    [parameter(ValueFromPipeline=1,ValueFromPipelineByPropertyName=1)][string[]] $Name,
    [ScriptBlock] $ScriptBlock, 
    [int] $Timeout = 30
    )
    $computers = $Name
    if($InputObject)
    {
        $computers = $InputObject | select -ExpandProperty Name
    }
    $timer = [Diagnostics.Stopwatch]::StartNew()
	$outerJob = Invoke-Command -ComputerName $computers -asjob -scriptblock $ScriptBlock
	$innerJobs = $outerJob.ChildJobs
	do
	{
		$mod = $innerJobs
		$innerJobs | wait-job -any -timeout 1 | % {
			$j = $_
			if(($j.State -eq 'Running' -or $j.State -eq 'Completed') -and $j.HasMoreData)
			{
				write-output "$($j.Location):"
				Receive-job -job $j
			}
			if($j.State -ne 'Running' -and $j.State -ne 'NotStarted')
			{
				write-output "$($j.Location): $($j.State)"
				$mod.Remove($j) | out-null
			}
		}
		$innerJobs = $mod
	} while ( $timer.Elapsed.TotalSeconds -lt $Timeout -and $outerJob.State -eq 'Running')
	if($outerJob.State -eq 'Running')
	{
		write-warning "Some jobs did not finish! Use Receive-Completed-Jobs"
		# some issue that will probably hang stop-job
		get-job -includechildjob
	}
	else
	{
		receive-job $outerJob
		remove-job $outerJob
	}
}

function Invoke-DC-Command
{
	Param([ScriptBlock] $ScriptBlock, [bool]$AllSites = $false, [int] $Timeout = 30)
	import-module ActiveDirectory

	$computers = @()
	if($AllSites)
	{
		$computers = Get-ADDomainController -Filter * -Server  (Get-ADDomain).dnsroot|select -ExpandProperty Hostname
	}
	else
	{
		#don't dig into the servers object except for .Name, it would try to connect to the machine right here
		$computers = [System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite().Servers | Select -ExpandProperty Name 
	}
    Invoke-Foreach-Computer -Name $computers -ScriptBlock $ScriptBlock -Timeout $Timeout
}

function Receive-Completed-Jobs
{
	get-job -includechildjob | % {
		if($_.State -eq 'Completed')
		{
			if($_.HasMoreData)
			{
				write-output "$($_.Location):"
				receive-job -job $_
			}
		}
	}
}

<#
.SYNOPSIS 
Gets recent events from the AuthLite Security event log on several servers

.PARAMETER servers
List of the servers to get events from
.PARAMETER seconds
Number of seconds ago to search
.PARAMETER match
String in the message to match

.EXAMPLE
Get-Events -servers dc1,nps -match duser1 -seconds 300 
#>
Function Get-Events()
{
    Param($servers, $seconds, $match)
    
    if($seconds -eq $null)
    {
        $seconds = 30
    }
    $since = (get-date) - (New-TimeSpan -Seconds $seconds)

    if($servers -eq $null)
    {
        $servers = "localhost"
    }

    if($match -eq $null)
    {
        $match = "*"
    }
    elseif(-not ($match -match '\*'))
    {
        $match = "*$match*"
    }
    $servers | foreach-object {Get-WinEvent -FilterHashTable @{LogName="AuthLite Security"; StartTime=$since} -Computername $_ -erroraction SilentlyContinue} | `
    where-object {$_.Message -like $match} `
    | sort-object TimeGenerated `
    | format-list -Property "MachineName", "EntryType", "EventID", "TimeGenerated", "Message"     
}




#THIS MUST BE LAST BEFORE SIG BLOCK
if($MyInvocation.UnboundArguments.Count -gt 0)
{
	# if the user wants to just run one thing instead of dotting in the script to current context, then oblige them
	# i.e. API.ps1 DoSomething withArgs etc...
	# this works by "splatting" https://stackoverflow.com/questions/31663208/invoke-expression-argument-splatting-with-sqlcmd
	$cmd = $MyInvocation.UnboundArguments[0]
	$a = $MyInvocation.UnboundArguments[1..$MyInvocation.UnboundArguments.Count]
	
    Invoke-Expression "$cmd @a"
	return
}

# ALL LINES BELOW ARE FOR THE AUTHENTICODE SIGNATURE
# A signature is provided so your systems can check that this script was created by AuthLite and not modified.
# All the signature lines are comments (start with #) so you can be assured there is nothing sneaky hiding in there! 

# SIG # Begin signature block
# MIIeeQYJKoZIhvcNAQcCoIIeajCCHmYCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU2VVi8bhAGrvd1HdGiiVobhEd
# QRigghm2MIIFszCCBJugAwIBAgIQB6xgbl6Q/NFRJN7Q7PNcLzANBgkqhkiG9w0B
# AQsFADBsMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMSswKQYDVQQDEyJEaWdpQ2VydCBFViBDb2Rl
# IFNpZ25pbmcgQ0EgKFNIQTIpMB4XDTE5MDIxNjAwMDAwMFoXDTIyMDUxNDEyMDAw
# MFowgcgxEzARBgsrBgEEAYI3PAIBAxMCVVMxGTAXBgsrBgEEAYI3PAIBAhMISWxs
# aW5vaXMxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMREwDwYDVQQFEwgw
# NTUyMzM5NzELMAkGA1UEBhMCVVMxETAPBgNVBAgTCElsbGlub2lzMRQwEgYDVQQH
# EwtTcHJpbmdmaWVsZDEWMBQGA1UEChMNQXV0aExpdGUsIExMQzEWMBQGA1UEAxMN
# QXV0aExpdGUsIExMQzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANlU
# TZuhauLu+vBotSLilyO5lVvGOCAXhO2klIgX5SBYs3ZV4d545zOl+UqETt1tDIsf
# hi3l74uFk2koOpMMvjUHFmyLLQIt01CLkVSxkgIjWgtXcAAa6YbGf3iKJQ3V8gfB
# Rh2NTmpCyd7I4Y4srbt3fw1AyM2vGTDcWKx7JdvGyRklAfMinNNhmnBmEL/n1sp+
# RtCrsnA/XH/1Obh7hQLa/XN1Pg9fPcRN3vXW8g2HTxVcsDjtM05R6E9BP5M0jI4c
# D0Gk9fhs3vhgivmmqxyWUFkavaOzHS1fsyJhXrxeRUiGu41lnOkaYdQ/zOV4BCYM
# oN9ThFU2I+gznE+5okMCAwEAAaOCAfIwggHuMB8GA1UdIwQYMBaAFI/ofvBtMmoA
# BSPHcJdqOpD/a+rUMB0GA1UdDgQWBBTS7OHfM+02dMVtyZexWhMzHLla5TAvBgNV
# HREEKDAmoCQGCCsGAQUFBwgDoBgwFgwUVVMtSUxMSU5PSVMtMDU1MjMzOTcwDgYD
# VR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMHsGA1UdHwR0MHIwN6A1
# oDOGMWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9FVkNvZGVTaWduaW5nU0hBMi1n
# MS5jcmwwN6A1oDOGMWh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9FVkNvZGVTaWdu
# aW5nU0hBMi1nMS5jcmwwSwYDVR0gBEQwQjA3BglghkgBhv1sAwIwKjAoBggrBgEF
# BQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzAHBgVngQwBAzB+Bggr
# BgEFBQcBAQRyMHAwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNv
# bTBIBggrBgEFBQcwAoY8aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lD
# ZXJ0RVZDb2RlU2lnbmluZ0NBLVNIQTIuY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZI
# hvcNAQELBQADggEBACG3goNR5sBDgbdluZoOj+3GEbyyfZdd4142t3mIKIddVd+F
# w8aMR/VgY5Me5oshXl7WQ3HoncN3j+Ytx9T/kcsSBW/XXCPLxKiVshBU8vISBWm6
# hD4br+MBaw8+bS6XE7b/+7OZH3AU4N3EvOi/90kdScDHb/klIa1IS41e/R3n+Dn4
# gy2d1Io9L6oxx9r8ZO514pqxHO6L5b85WCPRuvDwNxe2TgYzYZlNQO5w8v6YWSi6
# GBsxQOKStYu9m2lCI38hwNSdlDh+DXUFjBGfPGae7qQ59cYl97F2KSBwkBdTZg96
# pRnTm/nuvGOnQXlS22CFBkWIn4EOiircUCTyIvcwggZqMIIFUqADAgECAhADAZoC
# Ov9YsWvW1ermF/BmMA0GCSqGSIb3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMRUwEwYD
# VQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAf
# BgNVBAMTGERpZ2lDZXJ0IEFzc3VyZWQgSUQgQ0EtMTAeFw0xNDEwMjIwMDAwMDBa
# Fw0yNDEwMjIwMDAwMDBaMEcxCzAJBgNVBAYTAlVTMREwDwYDVQQKEwhEaWdpQ2Vy
# dDElMCMGA1UEAxMcRGlnaUNlcnQgVGltZXN0YW1wIFJlc3BvbmRlcjCCASIwDQYJ
# KoZIhvcNAQEBBQADggEPADCCAQoCggEBAKNkXfx8s+CCNeDg9sYq5kl1O8xu4FOp
# nx9kWeZ8a39rjJ1V+JLjntVaY1sCSVDZg85vZu7dy4XpX6X51Id0iEQ7Gcnl9ZGf
# xhQ5rCTqqEsskYnMXij0ZLZQt/USs3OWCmejvmGfrvP9Enh1DqZbFP1FI46GRFV9
# GIYFjFWHeUhG98oOjafeTl/iqLYtWQJhiGFyGGi5uHzu5uc0LzF3gTAfuzYBje8n
# 4/ea8EwxZI3j6/oZh6h+z+yMDDZbesF6uHjHyQYuRhDIjegEYNu8c3T6Ttj+qkDx
# ss5wRoPp2kChWTrZFQlXmVYwk/PJYczQCMxr7GJCkawCwO+k8IkRj3cCAwEAAaOC
# AzUwggMxMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQM
# MAoGCCsGAQUFBwMIMIIBvwYDVR0gBIIBtjCCAbIwggGhBglghkgBhv1sBwEwggGS
# MCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2VydC5jb20vQ1BTMIIBZAYI
# KwYBBQUHAgIwggFWHoIBUgBBAG4AeQAgAHUAcwBlACAAbwBmACAAdABoAGkAcwAg
# AEMAZQByAHQAaQBmAGkAYwBhAHQAZQAgAGMAbwBuAHMAdABpAHQAdQB0AGUAcwAg
# AGEAYwBjAGUAcAB0AGEAbgBjAGUAIABvAGYAIAB0AGgAZQAgAEQAaQBnAGkAQwBl
# AHIAdAAgAEMAUAAvAEMAUABTACAAYQBuAGQAIAB0AGgAZQAgAFIAZQBsAHkAaQBu
# AGcAIABQAGEAcgB0AHkAIABBAGcAcgBlAGUAbQBlAG4AdAAgAHcAaABpAGMAaAAg
# AGwAaQBtAGkAdAAgAGwAaQBhAGIAaQBsAGkAdAB5ACAAYQBuAGQAIABhAHIAZQAg
# AGkAbgBjAG8AcgBwAG8AcgBhAHQAZQBkACAAaABlAHIAZQBpAG4AIABiAHkAIABy
# AGUAZgBlAHIAZQBuAGMAZQAuMAsGCWCGSAGG/WwDFTAfBgNVHSMEGDAWgBQVABIr
# E5iymQftHt+ivlcNK2cCzTAdBgNVHQ4EFgQUYVpNJLZJMp1KKnkag0v0HonByn0w
# fQYDVR0fBHYwdDA4oDagNIYyaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lD
# ZXJ0QXNzdXJlZElEQ0EtMS5jcmwwOKA2oDSGMmh0dHA6Ly9jcmw0LmRpZ2ljZXJ0
# LmNvbS9EaWdpQ2VydEFzc3VyZWRJRENBLTEuY3JsMHcGCCsGAQUFBwEBBGswaTAk
# BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAC
# hjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURD
# QS0xLmNydDANBgkqhkiG9w0BAQUFAAOCAQEAnSV+GzNNsiaBXJuGziMgD4CH5Yj/
# /7HUaiwx7ToXGXEXzakbvFoWOQCd42yE5FpA+94GAYw3+puxnSR+/iCkV61bt5qw
# YCbqaVchXTQvH3Gwg5QZBWs1kBCge5fH9j/n4hFBpr1i2fAnPTgdKG86Ugnw7HBi
# 02JLsOBzppLA044x2C/jbRcTBu7kA7YUq/OPQ6dxnSHdFMoVXZJB2vkPgdGZdA0m
# xA5/G7X1oPHGdwYoFenYk+VVFvC7Cqsc21xIJ2bIo4sKHOWV2q7ELlmgYd3a822i
# YemKC23sEhi991VUQAOSK2vCUcIKSK+w1G7g9BQKOhvjjz3Kr2qNe9zYRDCCBrww
# ggWkoAMCAQICEAPxtOFfOoLxFJZ4s9fYR1wwDQYJKoZIhvcNAQELBQAwbDELMAkG
# A1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRp
# Z2ljZXJ0LmNvbTErMCkGA1UEAxMiRGlnaUNlcnQgSGlnaCBBc3N1cmFuY2UgRVYg
# Um9vdCBDQTAeFw0xMjA0MTgxMjAwMDBaFw0yNzA0MTgxMjAwMDBaMGwxCzAJBgNV
# BAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdp
# Y2VydC5jb20xKzApBgNVBAMTIkRpZ2lDZXJ0IEVWIENvZGUgU2lnbmluZyBDQSAo
# U0hBMikwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCnU/oPsrUT8WTP
# hID8roA10bbXx6MsrBosrPGErDo1EjqSkbpX5MTJ8y+oSDy31m7clyK6UXlhr0Mv
# DbebtEkxrkRYPqShlqeHTyN+w2xlJJBVPqHKI3zFQunEemJFm33eY3TLnmMl+ISa
# mq1FT659H8gTy3WbyeHhivgLDJj0yj7QRap6HqVYkzY0visuKzFYZrQyEJ+d8FKh
# 7+g+03byQFrc+mo9G0utdrCMXO42uoPqMKhM3vELKlhBiK4AiasD0RaCICJ2615U
# OBJi4dJwJNvtH3DSZAmALeK2nc4f8rsh82zb2LMZe4pQn+/sNgpcmrdK0wigOXn9
# 3b89OgklAgMBAAGjggNYMIIDVDASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB
# /wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDAzB/BggrBgEFBQcBAQRzMHEwJAYI
# KwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBJBggrBgEFBQcwAoY9
# aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0SGlnaEFzc3VyYW5j
# ZUVWUm9vdENBLmNydDCBjwYDVR0fBIGHMIGEMECgPqA8hjpodHRwOi8vY3JsMy5k
# aWdpY2VydC5jb20vRGlnaUNlcnRIaWdoQXNzdXJhbmNlRVZSb290Q0EuY3JsMECg
# PqA8hjpodHRwOi8vY3JsNC5kaWdpY2VydC5jb20vRGlnaUNlcnRIaWdoQXNzdXJh
# bmNlRVZSb290Q0EuY3JsMIIBxAYDVR0gBIIBuzCCAbcwggGzBglghkgBhv1sAwIw
# ggGkMDoGCCsGAQUFBwIBFi5odHRwOi8vd3d3LmRpZ2ljZXJ0LmNvbS9zc2wtY3Bz
# LXJlcG9zaXRvcnkuaHRtMIIBZAYIKwYBBQUHAgIwggFWHoIBUgBBAG4AeQAgAHUA
# cwBlACAAbwBmACAAdABoAGkAcwAgAEMAZQByAHQAaQBmAGkAYwBhAHQAZQAgAGMA
# bwBuAHMAdABpAHQAdQB0AGUAcwAgAGEAYwBjAGUAcAB0AGEAbgBjAGUAIABvAGYA
# IAB0AGgAZQAgAEQAaQBnAGkAQwBlAHIAdAAgAEMAUAAvAEMAUABTACAAYQBuAGQA
# IAB0AGgAZQAgAFIAZQBsAHkAaQBuAGcAIABQAGEAcgB0AHkAIABBAGcAcgBlAGUA
# bQBlAG4AdAAgAHcAaABpAGMAaAAgAGwAaQBtAGkAdAAgAGwAaQBhAGIAaQBsAGkA
# dAB5ACAAYQBuAGQAIABhAHIAZQAgAGkAbgBjAG8AcgBwAG8AcgBhAHQAZQBkACAA
# aABlAHIAZQBpAG4AIABiAHkAIAByAGUAZgBlAHIAZQBuAGMAZQAuMB0GA1UdDgQW
# BBSP6H7wbTJqAAUjx3CXajqQ/2vq1DAfBgNVHSMEGDAWgBSxPsNpA/i/RwHUmCYa
# CALvY2QrwzANBgkqhkiG9w0BAQsFAAOCAQEAGTNKDIEzN9utNsnkyTq7tRsueqLi
# 9ENCF56/TqFN4bHb6YHdnwHy5IjV6f4J/SHB7F2A0vDWwUPC/ncr2/nXkTPObNWy
# GTvmLtbJk0+IQI7N4fV+8Q/GWVZy6OtqQb0c1UbVfEnKZjgVwb/gkXB3h9zJjTHJ
# DCmiM+2N4ofNiY0/G//V4BqXi3zabfuoxrI6Zmt7AbPN2KY07BIBq5VYpcRTV6hg
# 5ucCEqC5I2SiTbt8gSVkIb7P7kIYQ5e7pTcGr03/JqVNYUvsRkG4Zc64eZ4IlguB
# jIo7j8eZjKMqbphtXmHGlreKuWEtk7jrDgRD1/X+pvBi1JlqpcHB8GSUgDCCBs0w
# ggW1oAMCAQICEAb9+QOWA63qAArrPye7uhswDQYJKoZIhvcNAQEFBQAwZTELMAkG
# A1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRp
# Z2ljZXJ0LmNvbTEkMCIGA1UEAxMbRGlnaUNlcnQgQXNzdXJlZCBJRCBSb290IENB
# MB4XDTA2MTExMDAwMDAwMFoXDTIxMTExMDAwMDAwMFowYjELMAkGA1UEBhMCVVMx
# FTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNv
# bTEhMB8GA1UEAxMYRGlnaUNlcnQgQXNzdXJlZCBJRCBDQS0xMIIBIjANBgkqhkiG
# 9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6IItmfnKwkKVpYBzQHDSnlZUXKnE0kEGj8kz
# /E1FkVyBn+0snPgWWd+etSQVwpi5tHdJ3InECtqvy15r7a2wcTHrzzpADEZNk+yL
# ejYIA6sMNP4YSYL+x8cxSIB8HqIPkg5QycaH6zY/2DDD/6b3+6LNb3Mj/qxWBZDw
# MiEWicZwiPkFl32jx0PdAug7Pe2xQaPtP77blUjE7h6z8rwMK5nQxl0SQoHhg26C
# cz8mSxSQrllmCsSNvtLOBq6thG9IhJtPQLnxTPKvmPv2zkBdXPao8S+v7Iki8msY
# ZbHBc63X8djPHgp0XEK4aH631XcKJ1Z8D2KkPzIUYJX9BwSiCQIDAQABo4IDejCC
# A3YwDgYDVR0PAQH/BAQDAgGGMDsGA1UdJQQ0MDIGCCsGAQUFBwMBBggrBgEFBQcD
# AgYIKwYBBQUHAwMGCCsGAQUFBwMEBggrBgEFBQcDCDCCAdIGA1UdIASCAckwggHF
# MIIBtAYKYIZIAYb9bAABBDCCAaQwOgYIKwYBBQUHAgEWLmh0dHA6Ly93d3cuZGln
# aWNlcnQuY29tL3NzbC1jcHMtcmVwb3NpdG9yeS5odG0wggFkBggrBgEFBQcCAjCC
# AVYeggFSAEEAbgB5ACAAdQBzAGUAIABvAGYAIAB0AGgAaQBzACAAQwBlAHIAdABp
# AGYAaQBjAGEAdABlACAAYwBvAG4AcwB0AGkAdAB1AHQAZQBzACAAYQBjAGMAZQBw
# AHQAYQBuAGMAZQAgAG8AZgAgAHQAaABlACAARABpAGcAaQBDAGUAcgB0ACAAQwBQ
# AC8AQwBQAFMAIABhAG4AZAAgAHQAaABlACAAUgBlAGwAeQBpAG4AZwAgAFAAYQBy
# AHQAeQAgAEEAZwByAGUAZQBtAGUAbgB0ACAAdwBoAGkAYwBoACAAbABpAG0AaQB0
# ACAAbABpAGEAYgBpAGwAaQB0AHkAIABhAG4AZAAgAGEAcgBlACAAaQBuAGMAbwBy
# AHAAbwByAGEAdABlAGQAIABoAGUAcgBlAGkAbgAgAGIAeQAgAHIAZQBmAGUAcgBl
# AG4AYwBlAC4wCwYJYIZIAYb9bAMVMBIGA1UdEwEB/wQIMAYBAf8CAQAweQYIKwYB
# BQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20w
# QwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2Vy
# dEFzc3VyZWRJRFJvb3RDQS5jcnQwgYEGA1UdHwR6MHgwOqA4oDaGNGh0dHA6Ly9j
# cmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwOqA4
# oDaGNGh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJv
# b3RDQS5jcmwwHQYDVR0OBBYEFBUAEisTmLKZB+0e36K+Vw0rZwLNMB8GA1UdIwQY
# MBaAFEXroq/0ksuCMS1Ri6enIZ3zbcgPMA0GCSqGSIb3DQEBBQUAA4IBAQBGUD7J
# tygkpzgdtlspr1LPUukxR6tWXHvVDQtBs+/sdR90OPKyXGGinJXDUOSCuSPRujqG
# cq04eKx1XRcXNHJHhZRW0eu7NoR3zCSl8wQZVann4+erYs37iy2QwsDStZS9Xk+x
# BdIOPRqpFFumhjFiqKgz5Js5p8T1zh14dpQlc+Qqq8+cdkvtX8JLFuRLcEwAiR78
# xXm8TBJX/l/hHrwCXaj++wc4Tw3GXZG5D2dFzdaD7eeSDY2xaYxP+1ngIw/Sqq4A
# fO6cQg7PkdcntxbuD8O9fAqg7iwIVYUiuOsYGk38KiGtSTGDR5V3cdyxG0tLHBCc
# dxTBnU8vWpUIKRAmMYIELTCCBCkCAQEwgYAwbDELMAkGA1UEBhMCVVMxFTATBgNV
# BAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTErMCkG
# A1UEAxMiRGlnaUNlcnQgRVYgQ29kZSBTaWduaW5nIENBIChTSEEyKQIQB6xgbl6Q
# /NFRJN7Q7PNcLzAJBgUrDgMCGgUAoHAwEAYKKwYBBAGCNwIBDDECMAAwGQYJKoZI
# hvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcC
# ARUwIwYJKoZIhvcNAQkEMRYEFEhneTYwM4M63Re7y/JDkmyxXFWFMA0GCSqGSIb3
# DQEBAQUABIIBANMQtG/qA47Yz1qeAmwtLUGo+pUEUbapgO9I+LcyEu08YtdnNE09
# O+fh/x9N8t5+SI26WkqAPMMchjTQOhNNsvMHxkdgVxs/6zX/tP59NTg7PbOE7DPA
# 0aJI4JEkqg8tJlElfKvEIw3nT74B6b0I4+XR9FgjAxqSLoZAy6CDbL5TwcfFdu1l
# uQuM0xFHcfgzO43LVUzuM+0mO42DND+rHmvIcUEtu3hcBNyDsDkbQ0qJCjHRYSoD
# aMcDplXi35FDo+Ck8EPYc2TaE4ZnARbIYF16Z0lA2nrvmtC9r500ArUlvHM06+hU
# itvSD5qZ2qbVKz+z3HtopAuZSeTCUK7842ehggIPMIICCwYJKoZIhvcNAQkGMYIB
# /DCCAfgCAQEwdjBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5j
# MRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBB
# c3N1cmVkIElEIENBLTECEAMBmgI6/1ixa9bV6uYX8GYwCQYFKw4DAhoFAKBdMBgG
# CSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTIwMDkxNzIy
# MDM1NFowIwYJKoZIhvcNAQkEMRYEFDjVlF6Ima011cqxWlfuw6M6vLT9MA0GCSqG
# SIb3DQEBAQUABIIBAFS3OMAhghwclHFBDLSvTq3mxqT4AgY+AGVhhVIx2Gu3PnYO
# 0ePsc0/wSIfSFnCG954DJbm8mMLFAJhr+gzZ2m2xETDJAns3NLugVe3wO3adtlQq
# GK/GY3TCnb8qjhBCIHIwDdI5yELY38kLiyJXu7e8qP4dz4+gcYYMmHf8qXI4rMLq
# QuRjKUN6MF4q6uLNVaHjIM/eU7npOhc3KI+G4r1AW6HLlGTWRvrVgpzVyEHqrQsq
# Yi2iv3wAayCb0hp3aNNqBmzwlA0z5O0aD7KL5PjSjV0Y47eU/iLgzkHRwXMZ+wVS
# UkjFsgpHJbmLuaZEijO12AyW+TZHE+NxqWtYzqc=
# SIG # End signature block
