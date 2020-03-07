function Invoke-GPPDeception {
    <#
    .SYNOPSIS

        This script generates a Group Policy Preferences file containing an encrypted cpasswd value. 
    
    .Description

        This script generates a Group Policy Preferences file containing an encrypted cpasswd value. This file replicates the file that would be
        created if GPP was used to create a local user on domain-joined machines.

    .Parameter Plaintext

        This is the plaintext password that will be used to generate the cpasswd.

    .Parameter $UserName

        This is the local username the GPP file would create.

    #>

    [cmdletbinding()]
    param(

        [Parameter(Position=1, Mandatory=$true)]
            [String]
            $Plaintext,

        [Parameter(Position=2, Mandatory=$true)]
            [String]
            $UserName
    )

    Set-Strictmode -Version 2

    try {
    
    $Diruid = New-Guid
    $DirUid = $Diruid.ToString().ToUpper()
    $DirUid = "{" + $DirUid + "}"
    
    $cPassword = Get-EncryptedCpassword $Plaintext
    
    $XMLString = GenXMLString $cPassword $UserName

    # Write out our pseudo-xml to a file
    Set-Content -Path 'groups.xml' -Value $XMLString

    Write-Host "`n`nWrote the following GPPDeception file to groups.xml.`n"
    Write-Host "Store it in the following path: " -NoNewline
    Write-Host "\\<FQDN>\sysvol\<FQDN>\" -ForegroundColor Yellow -NoNewline
    Write-Host $Diruid -ForegroundColor Yellow -NoNewLine
    Write-Host "\Machine\Preferences\Groups\groups.xml`n`n" -ForegroundColor Yellow
    Write-Host $XMLString

    }

    catch {Write-Error $Error[0]}

}

function Get-EncryptedCpassword {
    [cmdletbinding()]
    param(
    [String] $Plaintext
    )

       # Based on https://gist.githubusercontent.com/andreafortuna/6dc38f84f07fdadd1c90c41db7cd35e0/raw/ce97fec2f4f08fb63472de898122204147b2f90b/GPPDecrypt.ps1
       $AesObject = New-Object System.Security.Cryptography.AesCryptoServiceProvider
       # Public available AES key on https://msdn.microsoft.com/en-us/library/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be.aspx?f=255&MSPPError=-2147217396
       [Byte[]] $AesKey = @(0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
                            0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)

       $AesIV = New-Object Byte[]($AesObject.IV.Length) 
       $AesObject.IV = $AesIV
       $AesObject.Key = $AesKey

       # Convert password to Unicode Bytes
       $UnencryptedBytes = [System.Text.UnicodeEncoding]::Unicode.GetBytes($Plaintext)

       # Encrypt
       $Encryptor = $AesObject.CreateEncryptor()
       $EncryptedBytes = $Encryptor.TransformFinalBlock($UnencryptedBytes, 0, $UnencryptedBytes.Length)
            
       # store as byte array         
       [Byte[]] $FullData = $EncryptedBytes

       # Convert to Base64 for output
       $CipherText           = [System.Convert]::ToBase64String($FullData)

       # Remove padding from Base64 string
       $CipherText = $CipherText.TrimEnd("="," ")

       return $CipherText
}  

function GenXMLString {
    [cmdletbinding()]

    param(
    [String] $cPassword,
    [String] $UserName

    )

    # Generate an xml-like string to write to our file
    # Based on example found at: https://adsecurity.org/?p=384  
    # file header
    $header = '<?xml version="1.0" encoding="utf-8"?>'

    # Define GUIDs
    $GroupsClsid = New-Guid
    $GroupsClsid = $GroupsClsid.ToString().ToUpper()
    $GroupsClsid = "{" + $GroupsClsid + "}"

    $UserClsid = New-Guid
    $UserClsid = $UserClsid.ToString().ToUpper()
    $UserClsid = "{" + $UserClsid + "}"

    $uid = New-Guid
    $uid = $uid.ToString().ToUpper()
    $uid = "{" + $uid + "}"

    # Build our Groups string
    $GString = '<Groups clsid="' + $GroupsClsid + '">'

    # Build User String
    $date = Get-RandomDate

    $UString = '<User clsid="' + $UserClsid
    $UString += '" name="' + $UserName + '" '
    $UString += 'image="0" changed="' + $date + '" '
    $Ustring += 'uid="' + $uid + '">'

    # Build Properties String
    $PString = '<Properties action="C" fullName="" description="" '
    $PString += 'cpassword="' + $cPassword + '" '
    $PString += 'changeLogon="0" noChange="0" neverExpires="0" acctDisabled="0" userName="' + $UserName + '" />'
    $PString += "`n"
    $PString += '</User>'

    $FinalXML = $header
    $FinalXML += "`n"
    $FinalXML += $GString + "`n" + $UString + "`n" + $PString + "`n"
    $FinalXML += '</Groups>'

    return $FinalXML
    
}

function Get-RandomDate {
    
    # https://www.reddit.com/r/PowerShell/comments/77oeuz/getrandomdate/
    [DateTime] $Min = "01/01/2012 00:00:00"
    [DateTime] $Max = "12/31/2015 23:59:59"

    $randomTicks = Get-Random -Minimum $Min.Ticks -Maximum $Max.Ticks
    $DateString = New-Object DateTime($randomTicks)
    return $DateString.ToString("yyyy-mm-dd hh:mm:ss")

}

