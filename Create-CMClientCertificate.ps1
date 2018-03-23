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



## NEED TO ORGANIZE CODE ONCE FUNCTIONING AGAIN
## Thoughts are to add an initialization function that will load in the
## template configuration and check if the cert exists or not.

function Initialize-ScriptSettings ($param1, $param2) {

}

function Test-CATemplateExists ($param1, $param2) {

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
        Write-Host "Finding next available OID..."
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
        Write-Host "Last used ObjectID: $($lastUsedOid)"
        Write-Host "Setting msPKI-Cert-Template-OID $newOID"

        return $newOID
    }
}

# Variables
$ADSITemplate = @()
$TemplateName = 'ConfigMgr Client Certificate'
$TemplateDistinguishedName = 'ConfigMgrClientCertificate'

# CA Template Configurations
# DO NOT MODIFY
$ConfigMgrClientCertificateTemplate = @{
    'TemplateName'                      = 'ConfigMgr Client Certificate';
    'TemplateDistinguishedName'         = 'ConfigMgrClientCertificate';
    'ExistingTemplateName'              = 'Workstation Authentication';
    'flags'                             = '131680';
    'displayName'                       = 'ConfigMgr Client Certificate';
    'revision'                          = '100';
    'pKIDefaultKeySpec'                 = '1';
    'pKIMaxIssuingDepth'                = '0';
    'pKICriticalExtensions'             = '2.5.29.15';
    'pKIExtendedKeyUsage'               = '1.3.6.1.5.5.7.3.2'; # from ConfigMgrClientCertificate
    'pKIDefaultCSPs'                    = '1,Microsoft RSA SChannel Cryptographic Provider';
    'msPKIRASignature'                  = '0';
    'msPKIEnrollmentFlag'               = '32';
    'msPKIPrivateKeyFlag'               = '16842752';
    'msPKICertificateNameFlag'          = '134217728';
    'msPKIMinimalKeySize'               = '2048';
    'msPKITemplateSchemaVersion'        = '2';
    'msPKITemplateMinorRevision'        = '2';
    'msPKICertTemplateOID'              = "$(Get-NextObjectId)";
    'msPKICertificateApplicationPolicy' = '1.3.6.1.5.5.7.3.2'
}

# Check if the cert already exists and exit if it does
if ([bool](Get-CATemplate | Where-Object {$_.Name -match $ConfigMgrClientCertificateTemplate.TemplateDistinguishedName}) -eq 'True') {
    Write-Output "$TemplateName already exists existing..."
    Exit(0)
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
        [string]
        $UserOrGroupName,
        [System.DirectoryServices.ActiveDirectoryRights]
        $adRights = "ReadProperty, ExtendedRight, GenericExecute",
        [System.Security.AccessControl.AccessControlType]
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

        $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($identity, $adRights, $type)
        $ADSITemplate.psbase.ObjectSecurity.SetAccessRule($ACE)
        $ADSITemplate.psbase.CommitChanges()
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

        # TemplateConfiguration contains all the template attribrutes used to create the template
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        $TemplateConfiguration
        <#
        # Param2 help description
        [int]
        $Param2
        #>
    )

    Begin {
        Write-Host "Begin New-CATemplate $TemplateConfiguration.displayName CA Template..."
    }
    Process {
        # Get the current domain and create an ADSI object instance
        $ConfigContext = ([ADSI]"LDAP://RootDSE").ConfigurationNamingContext
        $ADSI = [ADSI]"LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext"

        $script:ADSITemplate = $ADSI.Create("pKICertificateTemplate", "CN=$($TemplateConfiguration.TemplateDistinguishedName)")
        $ADSITemplate.put("distinguishedName", "CN=$($TemplateConfiguration.TemplateDistinguishedName),CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext")
        # and put other atributes that you need

        $ADSITemplate.put("flags", $TemplateConfiguration.flags)
        $ADSITemplate.put("displayName", $TemplateConfiguration.displayName)
        $ADSITemplate.put("revision", $TemplateConfiguration.revision)
        $ADSITemplate.put("pKIDefaultKeySpec", $TemplateConfiguration.pKIDefaultKeySpec)
        $ADSITemplate.SetInfo()

        $ADSITemplate.put("pKIMaxIssuingDepth", $TemplateConfiguration.pKIMaxIssuingDepth)
        $ADSITemplate.put("pKICriticalExtensions", $TemplateConfiguration.pKICriticalExtensions)
        $ADSITemplate.put("pKIExtendedKeyUsage", $TemplateConfiguration.pKIExtendedKeyUsage)
        $ADSITemplate.put("pKIDefaultCSPs", $TemplateConfiguration.pKIDefaultCSPs)
        $ADSITemplate.put("msPKI-RA-Signature", $TemplateConfiguration.msPKIRASignature)
        $ADSITemplate.put("msPKI-Enrollment-Flag", $TemplateConfiguration.msPKIEnrollmentFlag)
        $ADSITemplate.put("msPKI-Private-Key-Flag", $TemplateConfiguration.msPKIPrivateKeyFlag)
        $ADSITemplate.put("msPKI-Certificate-Name-Flag", $TemplateConfiguration.msPKICertificateNameFlag)
        $ADSITemplate.put("msPKI-Minimal-Key-Size", $TemplateConfiguration.msPKIMinimalKeySize)
        $ADSITemplate.put("msPKI-Template-Schema-Version", $TemplateConfiguration.msPKITemplateSchemaVersion)
        $ADSITemplate.put("msPKI-Template-Minor-Revision", $TemplateConfiguration.msPKITemplateMinorRevision)
        $ADSITemplate.put("msPKI-Cert-Template-OID", "$(Get-NextObjectId)")
        $ADSITemplate.put("msPKI-Certificate-Application-Policy", $TemplateConfiguration.msPKICertificateApplicationPolicy)
        $ADSITemplate.SetInfo()

        # Get Workstation Authentication CA Template object
        $WATempl = $ADSI.psbase.children | Where-Object {$_.displayName -match $TemplateConfiguration.ExistingTemplateName}

        # Set pKIKeyUsage, pKIExpirationPeriod, pKIOverlapPeriod to the value in the Workstation Authentication template
        # These values I believe take a binary/array value and this was the easy way to make it work.
        $ADSITemplate.pKIKeyUsage = $WATempl.pKIKeyUsage
        $ADSITemplate.pKIExpirationPeriod = $WATempl.pKIExpirationPeriod
        $ADSITemplate.pKIOverlapPeriod = $WATempl.pKIOverlapPeriod
        $ADSITemplate.SetInfo()

        #$ADSITemplate | Select-Object *
    }
    End {
        Write-Host "End New-CATemplate $TemplateConfiguration.displayName CA Template..."
    }
}


New-CATemplate -TemplateConfiguration $ConfigMgrClientCertificateTemplate

Set-CATemplateAcl -UserOrGroupName 'CORP\Domain Computers'

# Get all the certificate templates (Issued&NonIssued from Active Directory)
$templates = $adsi | Select-Object -ExpandProperty Children
if ([bool]($templates.distinguishedName -match "CN=$($TemplateDistinguishedName),CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext") -eq 'True') {
    # Attempt to issue the Certificate Template
    Add-CATemplate -Name $TemplateDistinguishedName -Force -ErrorAction SilentlyContinue #-Verbose

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
        if ([bool](Get-CATemplate | Where-Object {$_.Name -match $TemplateDistinguishedName}) -eq 'True') {
            Write-Host "Template Publish Successfully-"
            $Stoploop = $true
        }
        else {Add-CATemplate -Name $($TemplateDistinguishedName) -Force -Verbose}
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