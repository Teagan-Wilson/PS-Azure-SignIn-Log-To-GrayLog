PARAM ($PastMinutes = 15 )
#************************************************
# AzureSignInToGrayLog.ps1
# Version 2.0
# Teagan Wilson - teagan.wilson@shicksolutions.com
# Azure AD Report Call baseed on Tim Springston's Graphs API reporting script:
# https://gallery.technet.microsoft.com/scriptcenter/Pull-Azure-AD-Sign-In-3fead683
# This script will require the Web Application and permissions setup in Azure Active Directory
#The MIT License (MIT)
#Copyright (c)
#Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
#The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.



$ClientID       = ""             #Client Application ID  from Azure AD - Should be a ~35 character string insert your info here
$ClientSecret   = ""         #Client Application Secret from Azure AD - Should be a ~44 character string insert your info here
$loginURL       = "https://login.windows.net"
$tenantdomain   = ""            # For example, contoso.onmicrosoft.com
$Tenantname = $tenantdomain.Split('.')[0]
$Uri = 'http://YourGraylogServerAddress:YourPort/gelf'

Write-Host "Collecting Azure AD Sign In reports for tenant $tenantdomain`."
function GetReport      ($url, $reportname, $tenantname) {
      $AuditOutputCSV = $Pwd.Path + "\" + (($tenantdomain.Split('.')[0]) + "_SignInReport.csv")
      # Get an Oauth 2 access token based on client id, secret and tenant domain
      $body       = @{grant_type="client_credentials";resource=$resource;client_id=$ClientID;client_secret=$ClientSecret}
      $oauth      = Invoke-RestMethod -Method Post -Uri $loginURL/$tenantdomain/oauth2/token?api-version=1.0 -Body $body
     if ($oauth.access_token -ne $null)
      {
      $Expiry = (Get-Date).AddSeconds($oauth.expires_in)
    $headerParams = @{'Authorization'="$($oauth.token_type) $($oauth.access_token)"}
    $myReport = (Invoke-WebRequest -UseBasicParsing -Headers $headerParams -Uri $url)
      $ConvertedReport = ConvertFrom-Json -InputObject $myReport.Content 
      $XMLReportValues = $ConvertedReport.value
      $nextURL = $ConvertedReport."@odata.nextLink"
	  
      if ($nextURL -ne $null)
            {
            Do 
            {
            $Soon = (Get-Date).AddSeconds(5)
            $TimeDifference = New-TimeSpan $Expiry $Soon
            if ($TimeDifference.Seconds -le 5)
            {
            $body = @{grant_type="client_credentials";resource=$resource;client_id=$ClientID;client_secret=$ClientSecret}
            $oauth = Invoke-RestMethod -Method Post -Uri $loginURL/$tenantdomain/oauth2/token?api-version=1.0 -Body $body
            $headerParams = @{'Authorization'="$($oauth.token_type) $($oauth.access_token)"}
            $Expiry = (Get-Date).AddSeconds($oauth.expires_in)
            }
            $NextResults = Invoke-WebRequest -UseBasicParsing -Headers $headerParams -Uri $nextURL -ErrorAction SilentlyContinue
            $NextConvertedReport = ConvertFrom-Json -InputObject $NextResults.Content 
            $XMLReportValues += $NextConvertedReport.value
            $nextURL = $NextConvertedReport."@odata.nextLink"
            }
            While ($nextURL -ne $null)
            }
            #Place results into a CSV
            $AuditOutputCSV = $Pwd.Path + "\" + $tenantname + "_$reportname.csv"
			move -Force -Path $AuditOutputCSV -Destination ($AuditOutputCSV + ".old")
      		$XMLReportValues | select *  |  Export-csv $AuditOutputCSV -NoTypeInformation -Force 
			
			$dups = Compare-Object $XMLReportValues (import-csv -path "C:\Users\twilson\Documents\shicksolutions_.csv.old") -Property id  -IncludeEqual
			$dups = Where-Object -InputObject $dups {($_.SideIndicator -eq "==") -or ($_.SideIndicator -eq "=>")}
			ForEach ($dup in $dups) { $XMLReportValues = $XMLReportValues | Where-Object { $_.id -ne $dup.id } }
			
			
			
            Write-Host "The report can be found at $AuditOutputCSV"
			
			($XMLReportValues | select *) | ForEach-Object {
			
			
		    
			$PSDefaultParameterValues.'Invoke-RestMethod:Uri' = $Uri.AbsoluteUri;
			$PSDefaultParameterValues.'Invoke-RestMethod:Method' = 'POST';
			$PSDefaultParameterValues.'Invoke-RestMethod:ContentType' = 'application/json';
			$PSDefaultParameterValues.'Invoke-RestMethod:Verbose' = $false;
			$Epoch = [Math]::Floor( [decimal] (Get-Date ((Get-Date).ToUniversalTime()) -UFormat '%s'));
			
			
			$item = New-Object –TypeName PSObject	
			Add-Member -InputObject $item –MemberType NoteProperty –Name version –Value ('1.1')
			Add-Member -InputObject $item –MemberType NoteProperty –Name host –Value ('Server')
			Add-Member -InputObject $item –MemberType NoteProperty –Name short_message –Value ('Office 365 Logons')
			Add-Member -InputObject $item –MemberType NoteProperty –Name GUID –Value ($_.ID)
			Add-Member -InputObject $item –MemberType NoteProperty –Name timestamp –Value ($_.signinDateTimeInMillis.ToString().Substring(0,10))
			Add-Member -InputObject $item –MemberType NoteProperty –Name userDisplayName –Value ($_.userDisplayName)
			Add-Member -InputObject $item –MemberType NoteProperty –Name userPrincipalName –Value ($_.userPrincipalName)
			Add-Member -InputObject $item –MemberType NoteProperty –Name userId –Value ($_.userId)
			Add-Member -InputObject $item –MemberType NoteProperty –Name appId –Value ($_.appId)
			Add-Member -InputObject $item –MemberType NoteProperty –Name ipAddress –Value ($_.ipAddress)
			Add-Member -InputObject $item –MemberType NoteProperty –Name loginStatus –Value ($_.loginStatus)
			Add-Member -InputObject $item –MemberType NoteProperty –Name deviceInformation –Value ($_.deviceInformation)
			Add-Member -InputObject $item –MemberType NoteProperty –Name ip_address_geolocation –Value (([string]$_.geoCoordinates.latitude + "," + [string]$_.geoCoordinates.longitude))
			Add-Member -InputObject $item –MemberType NoteProperty –Name location –Value ($_.location)
			Add-Member -InputObject $item –MemberType NoteProperty –Name ip_address_city_name –Value ($_.location.city)
			Add-Member -InputObject $item –MemberType NoteProperty –Name ip_address_country -Value ($_.location.country)
			Add-Member -InputObject $item –MemberType NoteProperty –Name signinErrorCode –Value ($_.signinErrorCode)
			Add-Member -InputObject $item –MemberType NoteProperty –Name failureReason –Value ($_.failureReason)
			$json = ConvertTo-Json -InputObject $item -Compress
			$null = Invoke-WebRequest -Uri $Uri -Body $json  -ContentType 'application/json' -Method POST
			
            }
  
	  }     
      if ($ConvertedReport.value.count -eq 0)
        {
        $AuditOutputCSV = $Pwd.Path + "\" + $tenantname + "_$reportname.txt"
        Get-Date |  Out-File -FilePath $AuditOutputCSV 
        "No Data Returned. This typically means either the tenant does not have Azure AD Premium licensing or that the report query succeeded however there were no entries in the report. " |  Out-File -FilePath $AuditOutputCSV -Append
        }
      }

if ($PastMinutes -ne $null)
	{
	$DateRaw = Get-Date
	$Date = ($DateRaw.Month.ToString()) + '-' + ($DateRaw.Day.ToString()) + "-" + ($DateRaw.Year.ToString())
	$PastPeriod =  "{0:s}" -f (get-date).ToUniversalTime().AddMinutes(-($PastMinutes)) + "Z"
	$filter = "`$filter=signinDateTime+ge+$PastPeriod"
	$url = "https://graph.windows.net/$tenantdomain/activities/signinEvents?api-version=beta&" + $filter
	GetReport $url $ReportName $Tenantname
	}
