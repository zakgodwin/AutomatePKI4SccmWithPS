#requires -version 4
<#
.SYNOPSIS
  Creates and issues ConfigMgr Client Certificate template.

.DESCRIPTION
  The script will find the next available Object identifier then use adsi to create and permission
  a CA template then issues the template using Add-CATemplate.

.PARAMETER <Parameter_Name>
  <Brief description of parameter input required. Repeat this attribute if required>

.INPUTS
  None

.OUTPUTS Log File
  The script log file stored in C:\Windows\Temp\<name>.log

.NOTES
  Version:        0.1
  Author:         Zak Godwin
  Creation Date:  03/15/2018
  Purpose/Change: Initial script development
  Links:          https://social.technet.microsoft.com/Forums/en-US/347acc93-8352-4535-ab1a-23ebd49eea22/duplicate-certificate-template-edit-and-publish-it?forum=winserverpowershell (The shell/template of the code to create a certificate with PowerShell.)
                  https://support.microsoft.com/en-us/help/287547/object-ids-associated-with-microsoft-cryptography (Microsoft OID reference)
                  https://docs.microsoft.com/en-us/sccm/core/plan-design/network/pki-certificate-requirements#BKMK_PKIcertificates_for_clients (Microsoft SCCM PKI Requirements)
                  https://technet.microsoft.com/en-us/library/gg682023.aspx#Deploying the Client Certificate for Windows Computers (Step by step to deploy PKI for use with SCCM)
  Note(0):        The script will create a CA template named ConfigMgr Client Certificate(ConfigMgrClientCertificate) the issueing bit is a little wonky is this version from experience it took about
                  a minute and a half for the certificate to show after refreshing the CA Console with having to break the script from running.
  Note(1):        Script doesn't have any logging, next available oid is rudimentary and the issueing of the template code is not that great.
  Note(2):        USE AT YOUR OWN RISK!
  Planned:        Fix issueing check and add logging.

.EXAMPLE
  <Example explanation goes here>

  <Example goes here. Repeat this attribute for more than one example>
#>

# Variables
$WorkstationTmplName = 'ConfigMgr Client Certificate'
$WorkstationTmplDistName = 'ConfigMgrClientCertificate'

# Check if the cert already exists and exit if it does
if ([bool](Get-CATemplate | Where-Object {$_.Name -match $WorkstationTmplDistName}) -eq 'True') {
    Write-Output "$WorkstationTmplName already exists existing..."
    Exit(0)
}

<#
.Synopsis
   Finds the next available Object Identifier
.DESCRIPTION
   The function will gather all CA Templates matching root OID 1.3.6.1.311.21.8.
   It then finds the last used index adds 1 digit and returns the new Oid string.
.EXAMPLE
   $newOID = Get-NextObjectId
.NOTE
   This has only been tested in a Server 2016 lab and not following and standards.
#>

function Get-NextObjectId {
    [CmdletBinding()]
    [Alias()]
    Param
    (
    )

    Begin {
        Write-Output "Finding next available OID..."
    }
    Process {
        $szOID_ENTERPRISE_OID_ROOT = '1.3.6.1.4.1.311.21.8.'
        # Get all enterprise specific oids
        # https://support.microsoft.com/en-us/help/287547/object-ids-associated-with-microsoft-cryptography
        $CertificateTemplates = (Get-CATemplate | Where-Object {$_.Oid -match $($szOID_ENTERPRISE_OID_ROOT)}).Oid


        [int]$highestOid = ''
        [string]$lastUsedOid = ''
        ForEach ($Oid in $CertificateTemplates) {
            $trimmedOid = $Oid.Replace($($szOID_ENTERPRISE_OID_ROOT), '')
            $arrayOid = $trimmedOid.Split('.')

            if ($highestOid -eq '' -or [int]$arrayOid[7] -gt $highestOid) {
                $highestOid = [int]$arrayOid[7]
                $lastUsedOid = $Oid
                # Write-Output "Highest Oid: $HighestOid"
            }

        }
    }
    End {
        $newIndexPosition = $lastUsedOid.LastIndexOf('.') + 1
        $newIndexValue = [int]$lastUsedOid.Substring($newIndexPosition) + 1
        $newOID = $lastUsedOid.Substring(0, $newIndexPosition) + $newIndexValue
        Write-Output "Last used ObjectID: $($lastUsedOid)"
        Write-Output "Setting msPKI-Cert-Template-OID $newOID"

        return $newOID
    }
}

<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
function Set-CATemplateAcl {
    [CmdletBinding()]
    Param
    (
        <#
        # Param1 help description
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $Param1,
        #>
        [System.DirectoryServices.DirectoryEntry]
        $NewTemplate,
        [string]
        $UserOrGroupName,
        [string]
        $adRights = "ReadProperty, ExtendedRight, GenericExecute",
        [string]
        $type = "Allow"


    )

    Begin {
        Write-Output "Adding $UserOrGroupName to certificate template ACL..."
        Write-Output "adRights: $adRights..."
        Write-Output "type: $type..."
    }
    Process {
        # Add Domain Computers to the Template ACL and permission
        $NTAccountPrincipal = New-Object System.Security.Principal.NTAccount($UserOrGroupName)
        $identity = $NTAccountPrincipal.Translate([System.Security.Principal.SecurityIdentifier])
        #$adRights = "ReadProperty, ExtendedRight, GenericExecute"
        #$type = "Allow"

        $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($identity, $adRights, $type)
        $NewTemplate.psbase.ObjectSecurity.SetAccessRule($ACE)
        $NewTemplate.psbase.commitchanges()
    }
    End {
        Write-Output "Completed adding $UserOrGroupName to certificate template ACL..."
    }
}

<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
function New-CATemplate {
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        <#
        # Param1 help description
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $Param1,

        # Param2 help description
        [int]
        $Param2
        #>
    )

    Begin {
    }
    Process {
    }
    End {
    }
}

$ConfigContext = ([ADSI]"LDAP://RootDSE").ConfigurationNamingContext
$ADSI = [ADSI]"LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext"

$NewTemplate = $ADSI.Create("pKICertificateTemplate", "CN=$($WorkstationTmplDistName)")
$NewTemplate.put("distinguishedName", "CN=$($WorkstationTmplDistName),CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext")
# and put other atributes that you need

$NewTemplate.put("flags", "131680")
$NewTemplate.put("displayName", "$($WorkstationTmplName)")
$NewTemplate.put("revision", "100")
$NewTemplate.put("pKIDefaultKeySpec", "1")
$NewTemplate.SetInfo()

$NewTemplate.put("pKIMaxIssuingDepth", "0")
$NewTemplate.put("pKICriticalExtensions", "2.5.29.15")
$NewTemplate.put("pKIExtendedKeyUsage", "1.3.6.1.5.5.7.3.2") # from ConfigMgrClientCertificate
$NewTemplate.put("pKIDefaultCSPs", "1,Microsoft RSA SChannel Cryptographic Provider")
$NewTemplate.put("msPKI-RA-Signature", "0")
$NewTemplate.put("msPKI-Enrollment-Flag", "32")
$NewTemplate.put("msPKI-Private-Key-Flag", "16842752")
$NewTemplate.put("msPKI-Certificate-Name-Flag", "134217728")
$NewTemplate.put("msPKI-Minimal-Key-Size", "2048")
$NewTemplate.put("msPKI-Template-Schema-Version", "2")
$NewTemplate.put("msPKI-Template-Minor-Revision", "2")
$NewTemplate.put("msPKI-Cert-Template-OID", "$(Get-NextObjectId)")
$NewTemplate.put("msPKI-Certificate-Application-Policy", "1.3.6.1.5.5.7.3.2")
$NewTemplate.SetInfo()

# Get Workstation Authentication CA Template object
$WATempl = $ADSI.psbase.children | Where-Object {$_.displayName -match "Workstation Authentication"}

# Set pKIKeyUsage, pKIExpirationPeriod, pKIOverlapPeriod to the value in the Workstation Authentication template
# These values I believe take a binary/array value and this was the easy way to make it work.
$NewTemplate.pKIKeyUsage = $WATempl.pKIKeyUsage
$NewTemplate.pKIExpirationPeriod = $WATempl.pKIExpirationPeriod
$NewTemplate.pKIOverlapPeriod = $WATempl.pKIOverlapPeriod
$NewTemplate.SetInfo()

$NewTemplate | Select-Object *

<# MOVING TO Set-CATemplateAcl
# Add Domain Computers to the Template ACL and permission
$NTAccountPrincipal = New-Object System.Security.Principal.NTAccount("Domain Computers")
$identity = $NTAccountPrincipal.Translate([System.Security.Principal.SecurityIdentifier])
$adRights = "ReadProperty, ExtendedRight, GenericExecute"
$type = "Allow"

$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($identity, $adRights, $type)
$NewTemplate.psbase.ObjectSecurity.SetAccessRule($ACE)
$NewTemplate.psbase.commitchanges()
#>

Set-CATemplateAcl -NewTemplate $NewTemplate

# Get all the certificate templates (Issued&NonIssued from Active Directory)
$templates = $adsi | Select-Object -ExpandProperty Children
if ([bool]($templates.distinguishedName -match "CN=$($WorkstationTmplDistName),CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext") -eq 'True') {
    # Attempt to issue the Certificate Template
    Add-CATemplate -Name $WorkstationTmplDistName -Force -ErrorAction SilentlyContinue #-Verbose

    # Stop and start the certificate services to speed up issuance
    Write-Output "Stoping CertSvc service..."
    Stop-Service CertSvc
    Sleep 5
    Write-Output "Starting CertSvc service..."
    while ((Get-Service -Name CertSvc).Status -ne 'Running') {
        Start-Service CertSvc
        Sleep 5
    }

}


# Loop until Certificate Template has been issued.
$Stoploop = $false
[int]$Retrycount = "0"

do {
    $templates = $adsi | Select-Object -ExpandProperty Children
    try {
        if ([bool](Get-CATemplate | Where-Object {$_.Name -match $WorkstationTmplDistName}) -eq 'True') {
            Write-Host "Template Publish Successfully-"
            $Stoploop = $true
        }
        else {Add-CATemplate -Name $($WorkstationTmplDistName) -Force -Verbose}
    }
    <# catch [EntryAlreadyExists]
    {
        Write-Host "Could not publish template, already exists..."
        $Stoploop = $true
    } #>
    catch {
        if ($Retrycount -gt 30) {
            Write-Host "Could not Publish Template after 3 retrys."
            $Stoploop = $true
        }
        else {
            Write-Host "Could not Publish Template, retrying in 30 seconds..."
            Start-Sleep -Seconds 30
            $Retrycount = $Retrycount + 1
        }
    }
}
While ($Stoploop -eq $false)