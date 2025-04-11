<#
.SYNOPSIS
This script enrolls a FIDO2 security key on behalf of a user in Microsoft Entra ID (formerly Azure AD).
Run the script as Administrator (required due to Windows FIDO2 Native API limitations).

.DESCRIPTION
The script connects to Microsoft Graph, creates a new credential on the security key using CTAP, 
and registers the key in Microsoft Entra ID. It uses the DSInternals.Passkeys module for passkey 
registration and Microsoft.Graph.Authentication module for Graph API interaction.
The user that connects to Microsoft Graph must have the Authentication Administrator role or 
UserAuthenticationMethod.ReadWrite.All Graph API permissions in Entra ID.

.PARAMETER UserUPN
The UPN of the user for whom the FIDO2 security key is being enrolled.

.PARAMETER PasskeyName
The name of the FIDO2 security key being enrolled. This will be displayed in the Authentication method list for the user.
The script appends the current date to the name and enforces a maximum length of 30 characters.

.EXAMPLE
.\Enroll-Fido2OnbehalfOf.ps1 -UserUPN "user@example.com" -PasskeyName "Keybrand-{serialnumber}"

.NOTES
Requires PowerShell 7.0 or later and the following modules:
- Microsoft.Graph.Authentication
- DSInternals.Passkeys

The script also generates a random 6-digit PIN for the security key, which is copied to the clipboard.
#>


#Requires -Version 7.0
#Requires -Module Microsoft.Graph.Authentication

#Define script parameters
param (
  [Parameter(
    mandatory=$true)][string]$UserUPN,
  [Parameter(
    mandatory=$true)][string]$PasskeyName
)

#Check if module is installed
if (-not (Get-Module -ListAvailable -Name DSInternals.Passkeys)) {
    Install-Module -Name DSInternals.Passkeys -Force
}

#Connect tot Microsoft Graph.
Connect-MgGraph -Scopes UserAuthenticationMethod.ReadWrite.All -NoWelcome

#Check if the user exists in Entra ID
$User = Get-MgUser -Filter "userPrincipalName eq '$UserUPN'" -ErrorAction SilentlyContinue
if (-not $User) {
    Write-Host "User $UserUPN not found in Entra ID." -ForegroundColor Red
    return
}

#Check if the user already has a FIDO2 key registered
# Retrieve the list of registered FIDO2 keys for the user
$Fido2Keys = Get-MgUserAuthenticationFido2Method -UserId $User.Id -ErrorAction SilentlyContinue

if ($Fido2Keys) {
  Write-Host "The user $UserUPN has the following FIDO2 keys registered:" -ForegroundColor Yellow
  $Fido2Keys | ForEach-Object { Write-Host "$($_.Id): $($_.DisplayName)" }

  # Prompt to remove a key
  $RemoveKey = Read-Host "Enter the ID of the FIDO2 key to remove, or press Enter to skip"
  if ($RemoveKey -and ($Fido2Keys.Id -contains $RemoveKey)) {
    Remove-MgUserAuthenticationFido2Method -UserId $User.Id -Fido2AuthenticationMethodId $RemoveKey -ErrorAction SilentlyContinue
    if ($?) {
      Write-Host "FIDO2 key with ID $RemoveKey has been removed." -ForegroundColor Green
    } else {
      Write-Host "Failed to remove the FIDO2 key with ID $RemoveKey." -ForegroundColor Red
    }
  } else {
    Write-Host "No key was removed. Continuing with enrollment." -ForegroundColor Yellow
  }
} else {
  Write-Host "No FIDO2 keys are currently registered for user $UserUPN." -ForegroundColor Green
}

#Add current date to $PasskeyName and enforce a maximum length of 30 characters
$CurrentDate = Get-Date -Format "yyyy-MM-dd"
$PasskeyName = $PasskeyName + "_" + $CurrentDate
$PasskeyName = $PasskeyName.Substring(0, [Math]::Min($PasskeyName.Length, 30))

#Generate a random 6 digit PIN for the security key
$Pin = Get-Random -Minimum 100000 -Maximum 999999

#Copy the PIN to the clipboard
Set-Clipboard -Value $Pin -ErrorAction SilentlyContinue
if ($?) {
    Write-Host "The PIN for the security key has been copied to the clipboard." -ForegroundColor Green
} else {
    Write-Host "Failed to copy the PIN to the clipboard." -ForegroundColor Red
} 

#Create new credential on the security key (using CTAP)
try {
  $Passkey = Get-PasskeyRegistrationOptions -UserId $UserUPN | New-Passkey -DisplayName $PasskeyName
  if (-not $Passkey) {
    throw "Failed to create a new credential on the security key."
  }
  Write-Host "Credential successfully created on the security key." -ForegroundColor Green
} catch {
  Write-Host "An error occurred while creating the credential on the security key: $_" -ForegroundColor Red
  return
}
 
#Prep the variables for Entra ID
#The following variables are used to register the key in Entra ID
$JSON = $Passkey | ConvertFrom-Json
$Attestationobject = $JSON.publicKeyCredential.response.attestationObject
$ClientDataJson = $JSON.publicKeyCredential.response.clientDataJSON
$id = $JSON.publicKeyCredential.id
 
#Prep the request for Graph API
$Body = @"
{
  "DisplayName": "$PasskeyName",
  "publicKeyCredential": {
    "id": "$ID",
    "response": {
      "clientDataJSON": "$clientDataJSON",
      "attestationObject": "$Attestationobject"
    }
  }
}
"@
 
#Register the key in Entra ID
$URI = "https://graph.microsoft.com/beta/users/$UserUPN/authentication/fido2Methods"
[string]$response = Invoke-MgGraphRequest -Method "POST" -Uri $URI -OutputType "Json" -ContentType 'application/json' -Body $Body

$response
