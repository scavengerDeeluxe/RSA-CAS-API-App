# ============================================================
# RSA SecurID CAS - API Request Builder GUI
# ============================================================
$URL = "YOUR.access.SPOT.com"
$AUTHURL = "YOUR.auth.SPOT.com"
$VAULTName= "YourSecretVault"
$JWKSecret = $YourJWKSecretName
$SecretClientID= $yourClientIDSecretName
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$script:SecureJwk = $null
# Initialize secure JWK storage
$script:SecureJwk = $null

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

[System.Windows.Forms.Application]::EnableVisualStyles()

# ============================================================
# JWT + Token functions (embedded so GUI is self-contained)
# ============================================================

function New-RSAJwtAssertion {
    param([string]$ClientId, [string]$TokenEndpointUrl, [string]$JwkJson)
        # Parse and validate JWK
        $jwk = $JwkJson | ConvertFrom-Json
        if (-not $jwk.kty -eq "RSA") {
            throw "Invalid key type. Expected 'RSA', got '$($jwk.kty)'"
        }

function ConvertFrom-Base64Url([string]$s) {
    $s = $s.Replace('-','+').Replace('_','/')
    switch ($s.Length % 4) { 2 { $s += '==' } 3 { $s += '=' } }
    [Convert]::FromBase64String($s)
}

        # Build RSA parameters with validation
        $rsaParams = [System.Security.Cryptography.RSAParameters]::new()

        $requiredParams = @('n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi')
        foreach ($param in $requiredParams) {
            if (-not $jwk.$param) {
                throw "Missing required JWK parameter: $param"
            }
        }

        $rsaParams.Modulus     = ConvertFrom-Base64Url $jwk.n
        $rsaParams.Exponent    = ConvertFrom-Base64Url $jwk.e
        $rsaParams.D           = ConvertFrom-Base64Url $jwk.d
        $rsaParams.P           = ConvertFrom-Base64Url $jwk.p
        $rsaParams.Q           = ConvertFrom-Base64Url $jwk.q
        $rsaParams.DP          = ConvertFrom-Base64Url $jwk.dp
        $rsaParams.DQ          = ConvertFrom-Base64Url $jwk.dq
        $rsaParams.InverseQ    = ConvertFrom-Base64Url $jwk.qi

        $rsa = [System.Security.Cryptography.RSA]::Create()
        $rsa.ImportParameters($rsaParams)

        # Build JWT header
        $headerObj =@{ alg = "RS256"; typ = "JWT"; kid = $jwk.kid } | ConvertTo-Json -Compress


        # Build JWT payload with proper timing
        $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $payload = @{
            iss = $ClientId
            sub = $ClientId
            aud = "https://$AUTHURL/oauth/token"
            jti = [guid]::NewGuid().ToString()
            iat = $now
            exp = $now + 300
        }

        $header = @{ alg = "RS256"; typ = "JWT"; kid = $jwk.kid } | ConvertTo-Json -Compress
        $payloadJson = $payload | ConvertTo-Json -Compress

function ConvertTo-Base64Url([byte[]]$bytes) {
    [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
}

        $hB64 = ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes($header))
        $pB64 = ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes($payloadJson))
        $si   = "$hB64.$pB64"

        $sig  = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($si),
                    [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                    [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $rsa.Dispose()

        $jwt = "$si.$(ConvertTo-Base64Url $sig)"

        # Decode and display parts for verification
        $parts = $jwt.Split('.')
        return $jwt

    }

function Get-RSACASToken {
    param([string]$ClientId, [string]$TokenUrl, [string]$JwkJson, [string]$Scope)
    $assertion = New-RSAJwtAssertion -ClientId $ClientId -TokenEndpointUrl $TokenUrl -JwkJson $JwkJson
    $body = @{
        grant_type            = "client_credentials"
        client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        client_assertion      = $assertion
        client_id             = $ClientId
        scope                 = $Scope
    }
    $resp = Invoke-RestMethod -Uri $TokenUrl -Method POST -ContentType "application/x-www-form-urlencoded" -Body $body
    return $resp.access_token
}

# ============================================================
# Presets
# ============================================================

$script:Presets = @{
    "Admin Logs" = @{
        Endpoint = "adminlog/exportlogs"
        Method   = "GET"
        Params   = @(
            @{ Key = "startTimeAfter";    Value = (Get-Date).ToUniversalTime().AddDays(-1).ToString("yyyy-MM-ddTHH:mm:ss.fff") + "Z" }
            @{ Key = "endTimeOnOrBefore"; Value = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fff") + "Z" }
            @{ Key = "pageNumber";        Value = "0" }
            @{ Key = "pageSize";          Value = "100" }
        )
    }
    "User Event Logs" = @{
        Endpoint = "usereventlog/exportlogs"
        Method   = "GET"
        Params   = @(
            @{ Key = "startTimeAfter";    Value = (Get-Date).ToUniversalTime().AddDays(-1).ToString("yyyy-MM-ddTHH:mm:ss.fff") + "Z" }
            @{ Key = "endTimeOnOrBefore"; Value = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fff") + "Z" }
            @{ Key = "pageNumber";        Value = "0" }
            @{ Key = "pageSize";          Value = "100" }
        )
    }
    "System Event Logs" = @{
        Endpoint = "systemlog/exportlogs"
        Method   = "GET"
        Params   = @(
            @{ Key = "startTimeAfter";    Value = (Get-Date).ToUniversalTime().AddDays(-1).ToString("yyyy-MM-ddTHH:mm:ss.fff") + "Z" }
            @{ Key = "endTimeOnOrBefore"; Value = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fff") + "Z" }
            @{ Key = "pageNumber";        Value = "0" }
            @{ Key = "pageSize";          Value = "100" }
        )
    }
    "User Auth Audit Logs" = @{
        Endpoint = "users/{userId}/authlogs"
        Method   = "GET"
        Params   = @(
            @{ Key = "userId";            Value = "" }
            @{ Key = "startTimeAfter";    Value = (Get-Date).ToUniversalTime().AddDays(-1).ToString("yyyy-MM-ddTHH:mm:ss.fff") + "Z" }
            @{ Key = "endTimeOnOrBefore"; Value = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fff") + "Z" }
            @{ Key = "eventCode";         Value = "" }
        )
    }
    "User Lookup" = @{
        Endpoint = "users/lookup"
        Method   = "POST"
        Params   = @(
            @{ Key = "email";            Value = "" }
            @{ Key = "searchUnsynched";  Value = "false" }
        )
    }
    "User Search v1" = @{
        Endpoint = "users/search"
        Method   = "POST"
        Params   = @(
            @{ Key = "emailLike"; Value = "" }
            @{ Key = "pageSize";     Value = "50" }
        )
    }
    "User Search v2" = @{
        Endpoint = "../v2/users/search"
        Method   = "POST"
        Params   = @(
            @{ Key = "emailLike"; Value = "" }
            @{ Key = "pageNumber";   Value = "0" }
            @{ Key = "pageSize";     Value = "50" }
        )
    }
    "User Sync" = @{
        Endpoint = "users/{guid}/sync"
        Method   = "POST"
        Params   = @(
            @{ Key = "guid"; Value = "" }
        )
    }
    "User Status Update" = @{
        Endpoint = "users/{userId}/userStatus"
        Method   = "PUT"
        Params   = @(
            @{ Key = "userId"; Value = "" }
            @{ Key = "userStatus"; Value = "Enabled" }
        )
    }
    "Create Local User" = @{
        Endpoint = "users/create"
        Method   = "POST"
        Params   = @(
            @{ Key = "firstName";             Value = "" }
            @{ Key = "lastName";              Value = "" }
            @{ Key = "userName";               Value = "" }
            @{ Key = "email";                  Value = "" }
            @{ Key = "identitySource";         Value = "Local Identity Source" }
            @{ Key = "passwordCreationOption"; Value = "NONE" }
            @{ Key = "passwordSendMethod";     Value = "NONE" }
        )
    }
    "Update Local User" = @{
        Endpoint = "users/update"
        Method   = "PUT"
        Params   = @(
            @{ Key = "id";                     Value = "" }
            @{ Key = "firstName";             Value = "" }
            @{ Key = "lastName";              Value = "" }
            @{ Key = "userName";               Value = "" }
            @{ Key = "email";                  Value = "" }
            @{ Key = "identitySource";         Value = "Local Identity Source" }
            @{ Key = "passwordCreationOption"; Value = "NONE" }
            @{ Key = "passwordSendMethod";     Value = "NONE" }
        )
    }
    "Mark User Deleted" = @{
        Endpoint = "users/{userId}/markDeleted"
        Method   = "PUT"
        Params   = @(
            @{ Key = "userId"; Value = "" }
            @{ Key = "markDeleted"; Value = "true" }
        )
    }
    "Delete User Now" = @{
        Endpoint = "users/{userId}"
        Method   = "DELETE"
        Params   = @(
            @{ Key = "userId"; Value = "" }
        )
    }
    "User Devices v1" = @{
        Endpoint = "users/{userId}/devices"
        Method   = "GET"
        Params   = @(
            @{ Key = "userId"; Value = "" }
            @{ Key = "includeBrowsers"; Value = "false" }
        )
    }
    "User Devices v2" = @{
        Endpoint = "../v2/users/{userId}/devices"
        Method   = "GET"
        Params   = @(
            @{ Key = "userId"; Value = "" }
            @{ Key = "includeBrowsers"; Value = "true" }
        )
    }
    "Delete User Device" = @{
        Endpoint = "users/{userId}/authenticators/{authenticatorId}"
        Method   = "DELETE"
        Params   = @(
            @{ Key = "userId";          Value = "" }
            @{ Key = "authenticatorId"; Value = "" }
        )
    }
    "Update SMS/Voice Phone" = @{
        Endpoint = "users/{userId}"
        Method   = "PATCH"
        Params   = @(
            @{ Key = "userId";    Value = "" }
            @{ Key = "smsNumber";  Value = "" }
            @{ Key = "voiceNumber"; Value = "" }
        )
    }
    "Unlock User Methods" = @{
        Endpoint = "users/{userId}/methods"
        Method   = "PATCH"
        Params   = @(
            @{ Key = "userId"; Value = "" }
            @{ Key = "unlockMethods"; Value = '["TOKEN", "SMS", "VOICE"]' }
        )
    }
    "Device Registration Code" = @{
        Endpoint = "deviceregistrationcode"
        Method   = "POST"
        Params   = @(
            @{ Key = "userIds";        Value = "" }
            @{ Key = "expirationTime"; Value = "24" }
        )
    }
    "Enable Emergency Token v1" = @{
        Endpoint = "users/{userId}/emergencytokencode"
        Method   = "PUT"
        Params   = @(
            @{ Key = "userId"; Value = "" }
            @{ Key = "enable"; Value = "true" }
        )
    }
    "Enable Emergency Token v2" = @{
        Endpoint = "users/{userId}/emergencytokencode/v2"
        Method   = "PUT"
        Params   = @(
            @{ Key = "userId"; Value = "" }
            @{ Key = "enable"; Value = "true" }
        )
    }
    "Disable Emergency Token" = @{
        Endpoint = "users/{userId}/emergencytokencode"
        Method   = "DELETE"
        Params   = @(
            @{ Key = "userId"; Value = "" }
        )
    }
    "Add High-Risk User" = @{
        Endpoint = "highriskusers"
        Method   = "POST"
        Params   = @(
            @{ Key = "userIds"; Value = "" }
            @{ Key = "reason";  Value = "" }
        )
    }
    "Remove High-Risk User" = @{
        Endpoint = "highriskusers"
        Method   = "DELETE"
        Params   = @(
            @{ Key = "userIds"; Value = "" }
        )
    }
    "High-Risk User List v1" = @{
        Endpoint = "highriskusers"
        Method   = "GET"
        Params   = @(
            @{ Key = "pageNumber"; Value = "0" }
            @{ Key = "pageSize";   Value = "100" }
        )
    }
    "High-Risk User List v2" = @{
        Endpoint = "highriskusers/v2"
        Method   = "GET"
        Params   = @(
            @{ Key = "pageNumber"; Value = "0" }
            @{ Key = "pageSize";   Value = "100" }
        )
    }
    "Anomalous Users" = @{
        Endpoint = "anomaloususers"
        Method   = "GET"
        Params   = @(
            @{ Key = "pageNumber"; Value = "0" }
            @{ Key = "pageSize";   Value = "100" }
        )
    }
    "License Usage" = @{
        Endpoint = "license/usage"
        Method   = "GET"
        Params   = @()
    }
    "Health Check" = @{
        Endpoint = "healthcheck"
        Method   = "GET"
        Params   = @()
    }
    "Assign Hardware Token" = @{
        Endpoint = "users/{userId}/hardwaretokens"
        Method   = "POST"
        Params   = @(
            @{ Key = "userId";      Value = "" }
            @{ Key = "serialNumber"; Value = "" }
        )
    }
    "Unassign Hardware Token" = @{
        Endpoint = "users/{userId}/hardwaretokens/{serialNumber}"
        Method   = "DELETE"
        Params   = @(
            @{ Key = "userId";       Value = "" }
            @{ Key = "serialNumber"; Value = "" }
        )
    }
    "Enable Hardware Token" = @{
        Endpoint = "users/{userId}/hardwaretokens/{serialNumber}/enable"
        Method   = "PUT"
        Params   = @(
            @{ Key = "userId";       Value = "" }
            @{ Key = "serialNumber"; Value = "" }
        )
    }
    "Disable Hardware Token" = @{
        Endpoint = "users/{userId}/hardwaretokens/{serialNumber}/disable"
        Method   = "PUT"
        Params   = @(
            @{ Key = "userId";       Value = "" }
            @{ Key = "serialNumber"; Value = "" }
        )
    }
    "Clear Hardware Token PIN" = @{
        Endpoint = "users/{userId}/hardwaretokens/{serialNumber}/clearpin"
        Method   = "PUT"
        Params   = @(
            @{ Key = "userId";       Value = "" }
            @{ Key = "serialNumber"; Value = "" }
        )
    }
    "Generate Enrollment Code" = @{
        Endpoint = "enrollmentcode"
        Method   = "POST"
        Params   = @(
            @{ Key = "userIds";        Value = "" }
            @{ Key = "expirationTime"; Value = "24" }
        )
    }
    "Void Enrollment Code" = @{
        Endpoint = "enrollmentcode"
        Method   = "DELETE"
        Params   = @(
            @{ Key = "userIds"; Value = "" }
        )
    }
    "Password Reset Code" = @{
        Endpoint = "passwordresetcode"
        Method   = "POST"
        Params   = @(
            @{ Key = "userIds";        Value = "" }
            @{ Key = "expirationTime"; Value = "24" }
        )
    }
    "Void Password Reset Code" = @{
        Endpoint = "passwordresetcode"
        Method   = "DELETE"
        Params   = @(
            @{ Key = "userIds"; Value = "" }
        )
    }
    "MFA Agent Lookup" = @{
        Endpoint = "mfaagent/lookup"
        Method   = "GET"
        Params   = @(
            @{ Key = "softwareId"; Value = "" }
            @{ Key = "hostname";   Value = "" }
        )
    }
    "FIDO Configuration Get" = @{
        Endpoint = "configuration/fido"
        Method   = "GET"
        Params   = @()
    }
    "FIDO Configuration Update" = @{
        Endpoint = "configuration/fido"
        Method   = "PATCH"
        Params   = @(
            @{ Key = "passkeyStatus"; Value = "false" }
            @{ Key = "minimumCertificationLevel"; Value = "FIDO_CERTIFIED_L2" }
            @{ Key = "allowedAuthenticatorsList"; Value = "" }
            @{ Key = "deniedAuthenticatorsList"; Value = "" }
            @{ Key = "allowedAuthenticatorsListEnabled"; Value = "true" }
            @{ Key = "deniedAuthenticatorsListEnabled"; Value = "true" }
        )
    }
    "FIDO Enable Authenticator" = @{
        Endpoint = "fido/{userId}/authenticators/{authenticatorId}/enable"
        Method   = "PATCH"
        Params   = @(
            @{ Key = "userId"; Value = "" }
            @{ Key = "authenticatorId"; Value = "" }
        )
    }
    "FIDO Disable Authenticator" = @{
        Endpoint = "fido/{userId}/authenticators/{authenticatorId}/disable"
        Method   = "PATCH"
        Params   = @(
            @{ Key = "userId"; Value = "" }
            @{ Key = "authenticatorId"; Value = "" }
        )
    }
    "Generate Verification Code" = @{
        Endpoint = "users/generateVerifyCode/enroll"
        Method   = "POST"
        Params   = @(
            @{ Key = "email"; Value = "" }
            @{ Key = "custom_email"; Value = "" }
            @{ Key = "code_validity"; Value = "10" }
            @{ Key = "validity_time_duration_unit"; Value = "MIN" }
            @{ Key = "code_send_to"; Value = "DISPLAY" }
        )
    }

    "Hardware Token Lookup" = @{
        Endpoint = "sidTokens/lookup"
        Method   = "POST"
        Params   = @(
            @{ Key = "tokenSerialNumber"; Value = "" }
        )
    }
    "Update Hardware Token Name" = @{
        Endpoint = "users/{userId}/sidTokens/updateName"
        Method   = "PATCH"
        Params   = @(
            @{ Key = "userId"; Value = "" }
            @{ Key = "tokenSerialNumber"; Value = "" }
            @{ Key = "updatedName"; Value = "" }
        )
    }
    "License Usage v2" = @{
        Endpoint = "../v2/licenseusage"
        Method   = "GET"
        Params   = @()
    }
    "Risk Dashboard Anomalous Users" = @{
        Endpoint = "riskdashboard/anomaloususerevents"
        Method   = "GET"
        Params   = @(
            @{ Key = "startTimeAfter";    Value = (Get-Date).ToUniversalTime().AddDays(-1).ToString("yyyy-MM-ddTHH:mm:ss.fff") + "Z" }
            @{ Key = "endTimeOnOrBefore"; Value = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fff") + "Z" }
        )
    }
    "Generate Report Users" = @{
        Endpoint = "report/users/generate"
        Method   = "POST"
        Params   = @()
    }
    "Generate Report Hardware Tokens" = @{
        Endpoint = "report/hardware_tokens/generate"
        Method   = "POST"
        Params   = @()
    }
    "Generate Report MFA Clients" = @{
        Endpoint = "report/mfa_clients/generate"
        Method   = "POST"
        Params   = @()
    }
    "User Verify Start" = @{
        Endpoint = "users/{userId}/verify/start"
        Method   = "POST"
        Params   = @(
            @{ Key = "userId"; Value = "" }
        )
    }
    "Custom" = @{
        Endpoint = ""
        Method   = "GET"
        Params   = @()
    }
}

# ============================================================
# Colors & Fonts
# ============================================================

$clrBg       = [System.Drawing.Color]::FromArgb(13,  17,  23)
$clrPanel    = [System.Drawing.Color]::FromArgb(22,  27,  34)
$clrBorder   = [System.Drawing.Color]::FromArgb(48,  54,  61)
$clrText     = [System.Drawing.Color]::FromArgb(201, 209, 217)
$clrMuted    = [System.Drawing.Color]::FromArgb(139, 148, 158)
$clrAccent   = [System.Drawing.Color]::FromArgb(56,  139, 253)
$clrGreen    = [System.Drawing.Color]::FromArgb(35,  134, 54)
$clrRed      = [System.Drawing.Color]::FromArgb(218, 54,  51)
$clrInput    = [System.Drawing.Color]::FromArgb(1,   4,   9)

$fontMono    = New-Object System.Drawing.Font("Cascadia Code", 9)
$fontMonoSm  = New-Object System.Drawing.Font("Cascadia Code", 8)
$fontLabel   = New-Object System.Drawing.Font("Cascadia Code", 7, [System.Drawing.FontStyle]::Bold)
$fontTitle   = New-Object System.Drawing.Font("Cascadia Code", 11, [System.Drawing.FontStyle]::Bold)

# ============================================================
# Main Form
# ============================================================

$form = New-Object System.Windows.Forms.Form
$form.Text            = "RSA SecurID CAS API Builder"
$form.Size            = New-Object System.Drawing.Size(920, 820)
$form.MinimumSize     = New-Object System.Drawing.Size(800, 700)
$form.BackColor       = $clrBg
$form.ForeColor       = $clrText
$form.Font            = $fontMono
$form.StartPosition   = "CenterScreen"
$form.FormBorderStyle = "Sizable"

# ============================================================
# Helper: styled label
# ============================================================
function New-Label($text, $x, $y, $w = 200, $h = 16) {
    $l = New-Object System.Windows.Forms.Label
    $l.Text      = $text.ToUpper()
    $l.Location  = New-Object System.Drawing.Point($x, $y)
    $l.Size      = New-Object System.Drawing.Size($w, $h)
    $l.ForeColor = $clrMuted
    $l.Font      = $fontLabel
    return $l
}

function New-Input($x, $y, $w, $h = 26, $text = "") {
    $tb = New-Object System.Windows.Forms.TextBox
    $tb.Location    = New-Object System.Drawing.Point($x, $y)
    $tb.Size        = New-Object System.Drawing.Size($w, $h)
    $tb.BackColor   = $clrInput
    $tb.ForeColor   = $clrText
    $tb.Font        = $fontMono
    $tb.BorderStyle = "FixedSingle"
    $tb.Text        = $text
    return $tb
}

function New-Button($text, $x, $y, $w = 110, $h = 28) {
    $b = New-Object System.Windows.Forms.Button
    $b.Text      = $text
    $b.Location  = New-Object System.Drawing.Point($x, $y)
    $b.Size      = New-Object System.Drawing.Size($w, $h)
    $b.BackColor = $clrPanel
    $b.ForeColor = $clrText
    $b.Font      = $fontMonoSm
    $b.FlatStyle = "Flat"
    $b.FlatAppearance.BorderColor = $clrBorder
    $b.FlatAppearance.BorderSize  = 1
    $b.Cursor    = "Hand"
    return $b
}

# ============================================================
# Title bar area
# ============================================================

$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text      = "RSA SecurID CAS ~ API Request Builder"
$lblTitle.Location  = New-Object System.Drawing.Point(20, 16)
$lblTitle.Size      = New-Object System.Drawing.Size(600, 26)
$lblTitle.ForeColor = [System.Drawing.Color]::FromArgb(240, 246, 252)
$lblTitle.Font      = $fontTitle
$form.Controls.Add($lblTitle)

$statusDot = New-Object System.Windows.Forms.Label
$statusDot.Text      = "•"
$statusDot.Location  = New-Object System.Drawing.Point(20, 44)
$statusDot.Size      = New-Object System.Drawing.Size(16, 14)
$statusDot.ForeColor = $clrMuted
$statusDot.Font      = $fontMonoSm
$form.Controls.Add($statusDot)

$lblStatus = New-Object System.Windows.Forms.Label
$lblStatus.Text      = "Not authenticated"
$lblStatus.Location  = New-Object System.Drawing.Point(38, 44)
$lblStatus.Size      = New-Object System.Drawing.Size(500, 14)
$lblStatus.ForeColor = $clrMuted
$lblStatus.Font      = $fontMonoSm
$form.Controls.Add($lblStatus)

# ============================================================
# Tab Control
# ============================================================

$tabs = New-Object System.Windows.Forms.TabControl
$tabs.Location  = New-Object System.Drawing.Point(14, 66)
$tabs.Size      = New-Object System.Drawing.Size(882, 710)
$tabs.BackColor = $clrBg
$tabs.Font      = $fontMonoSm
$form.Controls.Add($tabs)

# Dark tab styling
$tabs.DrawMode = "OwnerDrawFixed"
$tabs.ItemSize = New-Object System.Drawing.Size(130, 26)
$tabs.Add_DrawItem({
    param($s, $e)
    $tab    = $tabs.TabPages[$e.Index]
    $active = ($e.Index -eq $tabs.SelectedIndex)
    $bg     = if ($active) { $clrPanel } else { $clrBg }
    $fg     = if ($active) { $clrText  } else { $clrMuted }
    $e.Graphics.FillRectangle((New-Object System.Drawing.SolidBrush($bg)), $e.Bounds)

    # Calculate center position for text
    $textSize = $e.Graphics.MeasureString($tab.Text, $fontMonoSm)
    $x = $e.Bounds.X + ($e.Bounds.Width - $textSize.Width) / 2
    $y = $e.Bounds.Y + ($e.Bounds.Height - $textSize.Height) / 2
    $textPos = New-Object System.Drawing.PointF($x, $y)

    $e.Graphics.DrawString($tab.Text, $fontMonoSm, (New-Object System.Drawing.SolidBrush($fg)), $textPos)
})

function New-TabPage($title) {
    $tp = New-Object System.Windows.Forms.TabPage
    $tp.Text      = $title
    $tp.BackColor = $clrBg
    $tp.ForeColor = $clrText
    $tp.Font      = $fontMono
    $tabs.TabPages.Add($tp)
    return $tp
}

# ============================================================
# TAB 1 - AUTH
# ============================================================

$tabAuth = New-TabPage "[ Auth ]"
$y = 16

$tabAuth.Controls.Add((New-Label "Client ID" 16 $y))
$y += 18
$script:txtClientId = New-Input 16 $y 560 26 $clientid
$tabAuth.Controls.Add($script:txtClientId)
$y += 36

$tabAuth.Controls.Add((New-Label "Token Endpoint URL" 16 $y))
$y += 18
$script:txtTokenUrl = New-Input 16 $y 700 26 "https://$AUTHURL/oauth/token"
$tabAuth.Controls.Add($script:txtTokenUrl)
$y += 36

$tabAuth.Controls.Add((New-Label "Scope" 16 $y))
$y += 18
$script:txtScope = New-Input 16 $y 300 26 "rsa.audit.admin"
$tabAuth.Controls.Add($script:txtScope)
$y += 36

$tabAuth.Controls.Add((New-Label "JWK (JSON Web Key) - load from vault or paste" 16 $y))
$y += 18

$btnLoadVault = New-Button "Load from Vault" 16 $y 140
$btnLoadVault.ForeColor = [System.Drawing.Color]::FromArgb(121, 192, 255)
$btnLoadVault.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(31, 58, 95)
$tabAuth.Controls.Add($btnLoadVault)

$btnSaveVault = New-Button "Save to Vault" 162 $y 130
$tabAuth.Controls.Add($btnSaveVault)
$y += 36

$script:txtJwk = New-Object System.Windows.Forms.TextBox
$script:txtJwk.Location    = New-Object System.Drawing.Point(16, $y)
$script:txtJwk.Size        = New-Object System.Drawing.Size(840, 120)
$script:txtJwk.BackColor   = $clrInput
$script:txtJwk.ForeColor   = $clrText
$script:txtJwk.Font        = $fontMonoSm
$script:txtJwk.BorderStyle = "FixedSingle"
$script:txtJwk.Multiline   = $true
$script:txtJwk.ScrollBars  = "Vertical"
$script:txtJwk.Text        = '{"kty":"RSA","kid":"your-key-id","n":"...","e":"AQAB","d":"...","p":"...","q":"...","dp":"...","dq":"...","qi":"..."}'
$tabAuth.Controls.Add($script:txtJwk)
$y += 130

$btnGetToken = New-Button "Get Bearer Token" 16 $y 160 32
$btnGetToken.BackColor  = $clrGreen
$btnGetToken.ForeColor  = [System.Drawing.Color]::White
$btnGetToken.Font       = $fontMono
$btnGetToken.FlatAppearance.BorderColor = $clrGreen
$tabAuth.Controls.Add($btnGetToken)
$y += 42

$tabAuth.Controls.Add((New-Label "Bearer Token (active)" 16 $y))
$y += 18
$script:txtToken = New-Object System.Windows.Forms.TextBox
$script:txtToken.Location    = New-Object System.Drawing.Point(16, $y)
$script:txtToken.Size        = New-Object System.Drawing.Size(840, 26)
$script:txtToken.BackColor   = $clrInput
$script:txtToken.ForeColor   = [System.Drawing.Color]::FromArgb(121, 192, 255)
$script:txtToken.Font        = $fontMonoSm
$script:txtToken.BorderStyle = "FixedSingle"
$script:txtToken.ReadOnly    = $true
$tabAuth.Controls.Add($script:txtToken)

# Auth button events
$btnLoadVault.Add_Click({
    try {
        # Load JWK securely into variable (not displayed)
        $script:SecureJwk = Get-Secret -Vault $VAULTName -Name $JWKSecret -AsPlainText -ErrorAction Stop
        $script:txtClientId.Text = Get-Secret -Vault $VAULTName -Name $SecretClientID -AsPlainText -ErrorAction Stop

        # Show masked placeholder instead of actual JWK
        $script:txtJwk.Text = '{"kty":"RSA","kid":"*** LOADED FROM VAULT ***","n":"*** REDACTED ***","e":"*** REDACTED ***","d":"*** REDACTED ***"}'

        $lblStatus.Text = "Vault loaded OK (JWK secured)"
        $lblStatus.ForeColor = $clrGreen
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Vault load failed: $($_.Exception.Message)", "Vault Error", "OK", "Error")
    }
})

$btnSaveVault.Add_Click({
    try {
        # Use secure JWK if available, otherwise use text box content
        $jwkToSave = if ($script:SecureJwk) { $script:SecureJwk } else { $script:txtJwk.Text }

        # Don't save if it's the placeholder text
        if ($jwkToSave -notmatch '\*\*\* REDACTED \*\*\*') {
            Set-Secret -Vault $VaultName -Name $JWKSecret      -Secret $jwkToSave -ErrorAction Stop
            Set-Secret -Vault $vaultName -Name $SecretClientID -Secret $script:txtClientId.Text -ErrorAction Stop
            $lblStatus.Text      = "Saved to vault (JWK secured)"
            $lblStatus.ForeColor = $clrGreen
        } else {
            [System.Windows.Forms.MessageBox]::Show("Cannot save placeholder text. Enter actual JWK or load fresh from vault.", "Save Error", "OK", "Warning")
        }
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Vault save failed: $($_.Exception.Message)", "Vault Error", "OK", "Error")
    }
})

$btnGetToken.Add_Click({
    try {
        $btnGetToken.Text    = "Requesting..."
        $btnGetToken.Enabled = $false
        $form.Refresh()

        # Use secure JWK if loaded from vault, otherwise use text box content
        $jwkToUse = if ($script:SecureJwk) { $script:SecureJwk } else { $script:txtJwk.Text }

        $script:BearerToken = Get-RSACASToken `
            -ClientId     $script:txtClientId.Text `
            -TokenUrl     $script:txtTokenUrl.Text `
            -JwkJson      $jwkToUse `
            -Scope        $script:txtScope.Text

        $script:txtToken.Text = $script:BearerToken
        $statusDot.ForeColor  = $clrGreen
        $lblStatus.Text       = "Authenticated | Token: " + $script:BearerToken.Length + " chars | " + (Get-Date -Format 'HH:mm:ss')
        $lblStatus.ForeColor  = $clrGreen
    } catch {
        $statusDot.ForeColor = $clrRed
        $lblStatus.Text      = "Auth failed: " + $_.Exception.Message
        $lblStatus.ForeColor = $clrRed
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Token Error", "OK", "Error")
    } finally {
        $btnGetToken.Text    = "Get Bearer Token"
        $btnGetToken.Enabled = $true
    }
})

# ============================================================
# TAB 2 - REQUEST BUILDER
# ============================================================

$tabBuilder = New-TabPage "[ Builder ]"

# Left panel: controls
$pnlLeft = New-Object System.Windows.Forms.Panel
$pnlLeft.Location  = New-Object System.Drawing.Point(0, 0)
$pnlLeft.Size      = New-Object System.Drawing.Size(430, 680)
$pnlLeft.BackColor = $clrBg
$tabBuilder.Controls.Add($pnlLeft)

$y = 16

# Presets
$pnlLeft.Controls.Add((New-Label "Preset" 16 $y))
$y += 18
$cmbPreset = New-Object System.Windows.Forms.ComboBox
$cmbPreset.Location      = New-Object System.Drawing.Point(16, $y)
$cmbPreset.Size          = New-Object System.Drawing.Size(390, 26)
$cmbPreset.BackColor     = $clrInput
$cmbPreset.ForeColor     = $clrText
$cmbPreset.Font          = $fontMono
$cmbPreset.DropDownStyle = "DropDownList"
$cmbPreset.FlatStyle     = "Flat"
foreach ($k in $script:Presets.Keys) { $cmbPreset.Items.Add($k) | Out-Null }
$cmbPreset.SelectedItem = "Admin Logs"
$pnlLeft.Controls.Add($cmbPreset)
$y += 36

# Base URL
$pnlLeft.Controls.Add((New-Label "Base URL" 16 $y))
$y += 18
$script:txtBaseUrl = New-Input 16 $y 390 26 "https://$URL/AdminInterface/restapi/v1/"
$pnlLeft.Controls.Add($script:txtBaseUrl)
$y += 36

# Note label for API version
$lblVersion = New-Object System.Windows.Forms.Label
$lblVersion.Text      = "💡 Some APIs use /v2/ - check documentation"
$lblVersion.Location  = New-Object System.Drawing.Point(16, $y)
$lblVersion.Size      = New-Object System.Drawing.Size(390, 14)
$lblVersion.ForeColor = [System.Drawing.Color]::FromArgb(255, 204, 102)
$lblVersion.Font      = $fontMonoSm
$pnlLeft.Controls.Add($lblVersion)
$y += 20

# Endpoint + Method row
$pnlLeft.Controls.Add((New-Label "Endpoint Path" 16 $y))
$pnlLeft.Controls.Add((New-Label "Method" 300 $y))
$y += 18
$script:txtEndpoint = New-Input 16 $y 268 26 "adminlog/exportlogs"
$pnlLeft.Controls.Add($script:txtEndpoint)

$script:cmbMethod = New-Object System.Windows.Forms.ComboBox
$script:cmbMethod.Location      = New-Object System.Drawing.Point(292, $y)
$script:cmbMethod.Size          = New-Object System.Drawing.Size(114, 26)
$script:cmbMethod.BackColor     = $clrInput
$script:cmbMethod.ForeColor     = $clrText
$script:cmbMethod.Font          = $fontMono
$script:cmbMethod.DropDownStyle = "DropDownList"
$script:cmbMethod.FlatStyle     = "Flat"
@("GET","POST","PUT","DELETE") | ForEach-Object { $script:cmbMethod.Items.Add($_) | Out-Null }
$script:cmbMethod.SelectedItem = "GET"
$pnlLeft.Controls.Add($script:cmbMethod)
$y += 36

# Params header
$pnlLeft.Controls.Add((New-Label "Parameters (Key = Value)" 16 $y))
$btnAddParam = New-Button "+ Add" 310 ($y - 2) 96 22
$pnlLeft.Controls.Add($btnAddParam)
$y += 22

# Params container (scrollable)
$script:pnlParams = New-Object System.Windows.Forms.Panel
$script:pnlParams.Location   = New-Object System.Drawing.Point(16, $y)
$script:pnlParams.Size       = New-Object System.Drawing.Size(400, 260)
$script:pnlParams.BackColor  = $clrBg
$script:pnlParams.AutoScroll = $true
$pnlLeft.Controls.Add($script:pnlParams)
$y += 270

# Built URL preview label
$pnlLeft.Controls.Add((New-Label "Built URL" 16 $y))
$y += 18
$script:txtBuiltUrl = New-Object System.Windows.Forms.TextBox
$script:txtBuiltUrl.Location    = New-Object System.Drawing.Point(16, $y)
$script:txtBuiltUrl.Size        = New-Object System.Drawing.Size(390, 50)
$script:txtBuiltUrl.BackColor   = $clrInput
$script:txtBuiltUrl.ForeColor   = [System.Drawing.Color]::FromArgb(121, 192, 255)
$script:txtBuiltUrl.Font        = $fontMonoSm
$script:txtBuiltUrl.BorderStyle = "FixedSingle"
$script:txtBuiltUrl.Multiline   = $true
$script:txtBuiltUrl.ReadOnly    = $true
$pnlLeft.Controls.Add($script:txtBuiltUrl)

# Right panel: output
$pnlRight = New-Object System.Windows.Forms.Panel
$pnlRight.Location  = New-Object System.Drawing.Point(434, 0)
$pnlRight.Size      = New-Object System.Drawing.Size(440, 680)
$pnlRight.BackColor = $clrBg
$tabBuilder.Controls.Add($pnlRight)

$pnlRight.Controls.Add((New-Label "Response" 8 16))

$script:txtOutput = New-Object System.Windows.Forms.TextBox
$script:txtOutput.Location    = New-Object System.Drawing.Point(8, 34)
$script:txtOutput.Size        = New-Object System.Drawing.Size(424, 560)
$script:txtOutput.BackColor   = $clrInput
$script:txtOutput.ForeColor   = $clrText
$script:txtOutput.Font        = $fontMonoSm
$script:txtOutput.BorderStyle = "FixedSingle"
$script:txtOutput.Multiline   = $true
$script:txtOutput.ScrollBars  = "Both"
$script:txtOutput.ReadOnly    = $true
$script:txtOutput.WordWrap    = $false
$pnlRight.Controls.Add($script:txtOutput)

# Action buttons (bottom of right panel)
$btnSend = New-Button "Send Request" 8 602 140 32
$btnSend.BackColor  = $clrAccent
$btnSend.ForeColor  = [System.Drawing.Color]::White
$btnSend.Font       = $fontMono
$btnSend.FlatAppearance.BorderColor = $clrAccent
$pnlRight.Controls.Add($btnSend)

$btnCopyUrl = New-Button "Copy URL" 154 602 100 32
$pnlRight.Controls.Add($btnCopyUrl)

$btnSaveJson = New-Button "Save JSON" 260 602 100 32
$pnlRight.Controls.Add($btnSaveJson)

$btnClear = New-Button "Clear" 366 602 66 32
$pnlRight.Controls.Add($btnClear)

# ============================================================
# Param row management
# ============================================================

$script:ParamRows = [System.Collections.ArrayList]::new()

function Add-ParamRow($key = "", $value = "") {
    $rowY   = $script:ParamRows.Count * 32
    $rowPnl = New-Object System.Windows.Forms.Panel
    $rowPnl.Location  = New-Object System.Drawing.Point(0, $rowY)
    $rowPnl.Size      = New-Object System.Drawing.Size(390, 28)
    $rowPnl.BackColor = $clrBg

    $tbKey = New-Object System.Windows.Forms.TextBox
    $tbKey.Location    = New-Object System.Drawing.Point(0, 1)
    $tbKey.Size        = New-Object System.Drawing.Size(150, 24)
    $tbKey.BackColor   = $clrInput
    $tbKey.ForeColor   = [System.Drawing.Color]::FromArgb(210, 168, 255)
    $tbKey.Font        = $fontMonoSm
    $tbKey.BorderStyle = "FixedSingle"
    $tbKey.Text        = $key

    $tbVal = New-Object System.Windows.Forms.TextBox
    $tbVal.Location    = New-Object System.Drawing.Point(156, 1)
    $tbVal.Size        = New-Object System.Drawing.Size(200, 24)
    $tbVal.BackColor   = $clrInput
    $tbVal.ForeColor   = [System.Drawing.Color]::FromArgb(168, 218, 171)
    $tbVal.Font        = $fontMonoSm
    $tbVal.BorderStyle = "FixedSingle"
    $tbVal.Text        = $value

    $btnDel = New-Object System.Windows.Forms.Button
    $btnDel.Location  = New-Object System.Drawing.Point(362, 1)
    $btnDel.Size      = New-Object System.Drawing.Size(24, 24)
    $btnDel.Text      = "X"
    $btnDel.BackColor = $clrPanel
    $btnDel.ForeColor = $clrMuted
    $btnDel.Font      = $fontMono
    $btnDel.FlatStyle = "Flat"
    $btnDel.FlatAppearance.BorderSize = 0
    $btnDel.Cursor    = "Hand"

    $rowPnl.Controls.AddRange(@($tbKey, $tbVal, $btnDel))
    $script:pnlParams.Controls.Add($rowPnl)

    $row = @{ Panel = $rowPnl; Key = $tbKey; Value = $tbVal }
    $script:ParamRows.Add($row) | Out-Null

    # Delete handler
    $btnDel.Add_Click({
        $script:pnlParams.Controls.Remove($rowPnl)
        $script:ParamRows.Remove($row)
        # Re-layout remaining rows
        $i = 0
        foreach ($r in $script:ParamRows) {
            $r.Panel.Location = New-Object System.Drawing.Point(0, ($i * 32))
            $i++
        }
        Update-BuiltUrl
    }.GetNewClosure())

    # Live URL update
    $tbKey.Add_TextChanged({ Update-BuiltUrl })
    $tbVal.Add_TextChanged({ Update-BuiltUrl })
}

function Clear-ParamRows {
    $script:pnlParams.Controls.Clear()
    $script:ParamRows.Clear()
}

function Update-BuiltUrl {
    $base = $script:txtBaseUrl.Text.TrimEnd('/')
    $ep   = $script:txtEndpoint.Text.TrimStart('/')

    # Handle path parameter substitution
    $pathParams = [System.Collections.ArrayList]::new()
    $queryParams = [System.Collections.ArrayList]::new()

    foreach ($row in $script:ParamRows) {
        if ($row.Key.Text.Trim()) {
            $key = $row.Key.Text.Trim()
            $value = $row.Value.Text.Trim()

            # Check if this parameter is used in the path template
            if ($ep -match "\{$key\}") {
                $ep = $ep -replace "\{$key\}", [Uri]::EscapeDataString($value)
                $pathParams.Add($key) | Out-Null
            } else {
                # Regular query parameter
                $queryParams.Add("$([Uri]::EscapeDataString($key))=$([Uri]::EscapeDataString($value))") | Out-Null
            }
        }
    }

    $qs = if ($queryParams.Count -gt 0) { "?" + ($queryParams -join "&") } else { "" }
    $script:txtBuiltUrl.Text = "$base/$ep$qs"
}

# Wire live updates
$script:txtBaseUrl.Add_TextChanged({ Update-BuiltUrl })
$script:txtEndpoint.Add_TextChanged({ Update-BuiltUrl })

# Add param button
$btnAddParam.Add_Click({
    Add-ParamRow
    Update-BuiltUrl
})

# Preset selector
$cmbPreset.Add_SelectedIndexChanged({
    $p = $script:Presets[$cmbPreset.SelectedItem]
    $script:txtEndpoint.Text = $p.Endpoint
    $script:cmbMethod.SelectedItem = $p.Method
    Clear-ParamRows
    foreach ($param in $p.Params) { Add-ParamRow $param.Key $param.Value }
    Update-BuiltUrl
})

# Seed default params
foreach ($param in $script:Presets["Admin Logs"].Params) {
    Add-ParamRow $param.Key $param.Value
}
Update-BuiltUrl

# Send request
$btnSend.Add_Click({
    if (-not $script:BearerToken) {
        [System.Windows.Forms.MessageBox]::Show("Get a bearer token on the Auth tab first.", "No Token", "OK", "Warning")
        return
    }
    try {
        $btnSend.Text    = "Sending..."
        $btnSend.Enabled = $false
        $form.Refresh()

        $url     = $script:txtBuiltUrl.Text
        $method  = $script:cmbMethod.SelectedItem
        $headers = @{ Authorization = "Bearer $script:BearerToken"; Accept = "application/json" }

        if ($method -eq "GET") {
            $result = Invoke-RestMethod -Uri $url -Method GET -Headers $headers
        } else {
            # For POST/PUT/DELETE, build body from params (excluding path parameters)
            $ep = $script:txtEndpoint.Text.TrimStart('/')
            $bodyHash = @{}

            foreach ($r in $script:ParamRows) {
                if ($r.Key.Text.Trim()) {
                    $key = $r.Key.Text.Trim()
                    # Only include parameters that are NOT used in the path template
                    if ($ep -notmatch "\{$key\}") {
                        $bodyHash[$key] = $r.Value.Text
                    }
                }
            }

            if ($bodyHash.Count -gt 0) {
                $result = Invoke-RestMethod -Uri $url -Method $method -Headers $headers `
                    -ContentType "application/json" -Body ($bodyHash | ConvertTo-Json)
            } else {
                $result = Invoke-RestMethod -Uri $url -Method $method -Headers $headers
            }
        }

        $script:txtOutput.Text = $result | ConvertTo-Json -Depth 10
        $lblStatus.Text        = "200 OK  |  $(Get-Date -Format 'HH:mm:ss')  |  $url"
        $lblStatus.ForeColor   = $clrGreen
        $statusDot.ForeColor   = $clrGreen

    } catch {
        $code = if ($_.Exception.Response.StatusCode.value__) { $_.Exception.Response.StatusCode.value__ } else { "Unknown" }

        # Enhanced error display for parameter validation
        $errorDetails = ""
        if ($_.ErrorDetails.Message) {
            try {
                $errorJson = $_.ErrorDetails.Message | ConvertFrom-Json
                if ($errorJson.error_description) {
                    $errorDetails += "API Error: $($errorJson.error_description)`r`n`r`n"
                }
                if ($errorJson.message) {
                    $errorDetails += "Message: $($errorJson.message)`r`n`r`n"
                }
                $errorDetails += "Raw Response:`r`n$($_.ErrorDetails.Message)`r`n`r`n"
            } catch {
                $errorDetails += "Response Details:`r`n$($_.ErrorDetails.Message)`r`n`r`n"
            }
        }

        $script:txtOutput.Text = "ERROR $code`r`n`r`n$errorDetails`r`nException: $($_.Exception.Message)`r`n`r`nURL: $url`r`nMethod: $method"
        $lblStatus.Text        = "HTTP $code  |  $(Get-Date -Format 'HH:mm:ss') | Check response for parameter details"
        $lblStatus.ForeColor   = $clrRed
        $statusDot.ForeColor   = $clrRed
    } finally {
        $btnSend.Text    = "Send Request"
        $btnSend.Enabled = $true
    }
})

$btnCopyUrl.Add_Click({
    [System.Windows.Forms.Clipboard]::SetText($script:txtBuiltUrl.Text)
    $btnCopyUrl.Text = "Copied!"
    $btnCopyUrl.ForeColor = $clrGreen
    Start-Sleep -Milliseconds 1200
    $btnCopyUrl.Text = "Copy URL"
    $btnCopyUrl.ForeColor = $clrText
})

$btnSaveJson.Add_Click({
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Filter   = "JSON files (*.json)|*.json|All files (*.*)|*.*"
    $dlg.FileName = "rsa-response-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    if ($dlg.ShowDialog() -eq "OK") {
        $script:txtOutput.Text | Out-File -FilePath $dlg.FileName -Encoding utf8
        $lblStatus.Text      = "Saved to $($dlg.FileName)"
        $lblStatus.ForeColor = $clrGreen
    }
})

$btnClear.Add_Click({ $script:txtOutput.Text = "" })

# ============================================================
# TAB 3 - PS SNIPPET
# ============================================================

$tabSnippet = New-TabPage "[ PS Snippet ]"

$tabSnippet.Controls.Add((New-Label "Generated PowerShell Snippet" 16 16))

$btnGenSnippet = New-Button "Generate from Builder" 16 34 190 28
$btnGenSnippet.ForeColor = [System.Drawing.Color]::FromArgb(121, 192, 255)
$btnGenSnippet.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(31, 58, 95)
$tabSnippet.Controls.Add($btnGenSnippet)

$btnCopySnippet = New-Button "Copy to Clipboard" 212 34 160 28
$tabSnippet.Controls.Add($btnCopySnippet)

$txtSnippet = New-Object System.Windows.Forms.TextBox
$txtSnippet.Location    = New-Object System.Drawing.Point(16, 70)
$txtSnippet.Size        = New-Object System.Drawing.Size(848, 590)
$txtSnippet.BackColor   = $clrInput
$txtSnippet.ForeColor   = $clrText
$txtSnippet.Font        = $fontMonoSm
$txtSnippet.BorderStyle = "FixedSingle"
$txtSnippet.Multiline   = $true
$txtSnippet.ScrollBars  = "Both"
$txtSnippet.WordWrap    = $false
$tabSnippet.Controls.Add($txtSnippet)

$btnGenSnippet.Add_Click({
    $url    = $script:txtBuiltUrl.Text
    $method = $script:cmbMethod.SelectedItem
    $ep     = $script:txtEndpoint.Text.TrimStart('/')

    if ($method -eq "GET") {
        # Separate path params from query params
        $queryParamLines = ($script:ParamRows | Where-Object {
            $_.Key.Text.Trim() -and ($ep -notmatch "\{$($_.Key.Text.Trim())\}")
        } | ForEach-Object {
            "`$queryParams.Add(`"$($_.Key.Text)=`" + [Uri]::EscapeDataString(`"$($_.Value.Text)`"))"
        }) -join "`r`n"

        $pathSubstitutions = ($script:ParamRows | Where-Object {
            $_.Key.Text.Trim() -and ($ep -match "\{$($_.Key.Text.Trim())\}")
        } | ForEach-Object {
            "`$endpoint = `$endpoint -replace `"\{$($_.Key.Text)\}`", [Uri]::EscapeDataString(`"$($_.Value.Text)`")"
        }) -join "`r`n"

        $snippet = @"
# --- Auto-generated by RSA API Builder ---
# Endpoint: $url

`$endpoint = "$($script:txtBaseUrl.Text.TrimEnd('/'))/$ep"

$(if ($pathSubstitutions) { "# Path parameter substitutions`r`n$pathSubstitutions`r`n" })$(if ($queryParamLines) { "`$queryParams = [System.Collections.Generic.List[string]]::new()`r`n$queryParamLines`r`n`$endpoint += `"?`" + (`$queryParams -join `"&`")`r`n" })

`$result = Invoke-RestMethod ``
    -Uri     `$endpoint ``
    -Method  GET ``
    -Headers @{
        Authorization = "Bearer `$token"
        Accept        = "application/json"
    }

`$result | ConvertTo-Json -Depth 10
`$result | ConvertTo-Json -Depth 10 | Out-File -FilePath "response-$(Get-Date -Format 'yyyyMMdd-HHmmss').json" -Encoding utf8
"@
    } else {
        # Separate path params from body params
        $bodyLines = ($script:ParamRows | Where-Object {
            $_.Key.Text.Trim() -and ($ep -notmatch "\{$($_.Key.Text.Trim())\}")
        } | ForEach-Object {
            "    $($_.Key.Text) = `"$($_.Value.Text)`""
        }) -join "`r`n"

        $pathSubstitutions = ($script:ParamRows | Where-Object {
            $_.Key.Text.Trim() -and ($ep -match "\{$($_.Key.Text.Trim())\}")
        } | ForEach-Object {
            "`$endpoint = `$endpoint -replace `"\{$($_.Key.Text)\}`", [Uri]::EscapeDataString(`"$($_.Value.Text)`")"
        }) -join "`r`n"

        $snippet = @"
# --- Auto-generated by RSA API Builder ---
# Endpoint: Built dynamically with path substitution

`$endpoint = "$($script:txtBaseUrl.Text.TrimEnd('/'))/$ep"

$(if ($pathSubstitutions) { "# Path parameter substitutions`r`n$pathSubstitutions`r`n" })$(if ($bodyLines) { "`$body = @{`r`n$bodyLines`r`n} | ConvertTo-Json`r`n" } else { "`$body = `$null`r`n" })

`$result = Invoke-RestMethod ``
    -Uri         `$endpoint ``
    -Method      $method ``$(if ($bodyLines) { "    -ContentType `"application/json`" ```r`n    -Body        `$body ``" })
    -Headers     @{ Authorization = "Bearer `$token" }

`$result | ConvertTo-Json -Depth 10
`$result | ConvertTo-Json -Depth 10 | Out-File -FilePath "response-$(Get-Date -Format 'yyyyMMdd-HHmmss').json" -Encoding utf8
"@
    }

    $txtSnippet.Text = $snippet
})

$btnCopySnippet.Add_Click({
    if ($txtSnippet.Text) {
        [System.Windows.Forms.Clipboard]::SetText($txtSnippet.Text)
        $btnCopySnippet.Text = "Copied!"
        $btnCopySnippet.ForeColor = $clrGreen
        Start-Sleep -Milliseconds 1200
        $btnCopySnippet.Text = "Copy to Clipboard"
        $btnCopySnippet.ForeColor = $clrText
    }
})

# ============================================================
# Run
# ============================================================

[System.Windows.Forms.Application]::Run($form)
