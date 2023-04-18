# Set variables.
$csv = "c:\...\users.csv"
$domain = Get-ADDomain
$folder = "c:\...\"
$count = 0

# Password generator.
$newPass = ''
1..12 | ForEach-Object {$newPass += [char](Get-Random -Minimum 48 -Maximum 122)}

# Create destination folder.
function folder
{
    if(Test-Path $folder){}
    else{New-Item -Path $folder -ItemType Directory -Force}
}

# Main menu.
function menu
{
 cls
 $option = Read-Host "Select option:`n 1 – User accounts`n 2 - Group accounts`n 3 - Reports`n q - Exit"`n
 if($option -eq 1){a}
 elseif($option -eq 2){b}
 elseif($option -eq 3){c}
 elseif($option -eq 'q'){break}
  else
    {
     Write-Host "Error - select correct option" -ForegroundColor Red
     Sleep 2
     menu
    }
}

# User accounts submenu.
function a
{
 cls
 $option = Read-Host "Select option:`n 1 – Create user account`n 2 - Import accounts from csv file`n 3 - Block user account`n 4 - Change user account password`n q - Back"`n
 if($option -eq 1){create_account}
 elseif($option -eq 2){csv}
 elseif($option -eq 3){block_account}
 elseif($option -eq 4){change_password}
  elseif($option -eq 'q'){menu}
 else
    {
     Write-Host "Error - select correct option" -ForegroundColor Red
     Sleep 2
     a
    }
}

# Group accounts submenu.
function b
{
 cls
 $option = Read-Host "Select option:`n 1 – Create new group`n 2 - Add user to group`n q - Back"`n
 if($option -eq 1){create_group}
 elseif($option -eq 2){add_to_group}
  elseif($option -eq 'q'){menu}
 else
    {
     Write-Host "Error - select correct option" -ForegroundColor Red
     Sleep 2
     b
    }
}

# Reports submenu.
function c
{
 cls
 $option = Read-Host "Select option:`n 1 – List group with members`n 2 - List blocked accounts`n 3 - List user accounts details`n 4 - List domain computers details`n 5 - List organizational units`n q - Back"`n
 if($option -eq 1){group_list}
 elseif($option -eq 2){list_blocked}
 elseif($option -eq 3){list_accounts}
 elseif($option -eq 4){list_computers}
 elseif($option -eq 5){list_ou}
 elseif($option -eq 'q'){menu}
 else
    {
     Write-Host "Error - select correct option" -ForegroundColor Red
     Sleep 2
     c
    }
}

# Create user account.
function create_account
{
    [CmdletBinding()]
    param(
    [Parameter(Mandatory=$true)]
    [string]$name,
    [Parameter(Mandatory=$true)]
    [string]$surname,
    [Parameter(Mandatory=$true)]
    [string]$department
    )
    $logindns = "$($name).$($surname)"
    $logindns2 = $logindns+"@"+$domain.DNSRoot
    $username = "$($name) $($surname)"
    $count = 0
    $file = $folder+"$($username).csv" 
    while((Get-ADuser -Filter {SamAccountName -eq $logindns}))
    {
        $count++
        $logindns = $logindns + [string]$count
        $logindns2 = $logindns+"@"+$domain.DNSRoot
        $username = $username + [string]$count
        $file = $folder+"$($username).csv"
    }
    New-ADUser -DisplayName:$username -EmailAddress:$logindns2 -Department:$department -GivenName:$name -Name:$username -SamAccountName:$logindns -Surname:$surname -Type:"user" -UserPrincipalName:$logindns2 -AccountPassword (ConvertTo-SecureString $newPass -AsPlainText -Force) -Enabled:$true
    Get-ADUser $logindns | Export-Csv $file -NoTypeInformation
    "Password: " + $newPass >> $file
    $log = "Creator User Date" | ConvertFrom-String | Export-Csv -Path $folder"create_user.csv" -NoClobber -NoTypeInformation
    $who = Get-ADUser $env:USERNAME 
    $date = Get-Date -Format "MM/dd/yyyy HH:mm"
    $log = "$($who.Name);$username;$date" | ConvertFrom-String -Delimiter ";" | Export-Csv -Path $folder"create_user.csv" -NoClobber -NoTypeInformation -Append
    a
}

# Import from accounts from csv.
function create_account_csv
{
    $users = Import-Csv $csv
    Foreach ($user in $users)
    {  
        $dane = [pscustomobject]@{
                    Name = $user.name + " " + $user.surname
                    GivenName = $user.name
                    Surname = $user.surname
                    Department = $user.department
                    UserPrincipalName = $user.name + "." + $user.surname + "@" + $domain.DNSRoot
                    SamAccountName = $user.name + "." + $user.surname
                    DisplayName = $user.name + " " + $user.surname
                    EmailAddress = $user.name + "." + $user.surname + "@" + $domain.DNSRoot
                    AccountPassword = ConvertTo-SecureString $newPass -AsPlainText -Force
                    Enabled = $true
                 }
        $count = 0
        $adusers = Get-ADUser -Filter * | Select-Object SamAccountName | % {
        $aduser = $_
        if ($aduser.SamAccountName -eq $dane.SamAccountName)
        {
            $count++
            $dane.SamAccountName = $dane.SamAccountName + [string]$count
            $dane.UserPrincipalName = $dane.SamAccountName+"@"+$domain.DNSRoot
            $dane.Name = $dane.Name + [string]$count
        }     
        }
        $dane | New-ADUser -PassThru
        $log = "Creator User Date" | ConvertFrom-String | Export-Csv -Path $folder"create_user.csv" -NoClobber -NoTypeInformation
        $who = Get-ADUser $env:USERNAME 
        $date = Get-Date -Format "MM/dd/yyyy HH:mm"
        $log = "$($who.Name);$($dane.Name);$date" | ConvertFrom-String -Delimiter ";" | Export-Csv -Path $folder"create_user.csv" -NoClobber -NoTypeInformation -Append
    }
    a
}

# Generate empty csv file.
function csv
{
    cls
    $option = Read-Host "Select option:`n 1 - Import accounts from csv`n 2 - Generate empty csv`n q - Back"`n
    if($option -eq 1){create_account_csv}
    elseif($option -eq 2){
                            $header = "name","surname","department" | Select-Object name,surname,department | Export-Csv -Path $csv -NoClobber -NoTypeInformation
                            a
                        }
    elseif($option -eq 'q'){a}
    else
    {
        Write-Host "Error - select correct option" -ForegroundColor Red
        Sleep 2
        a
    }
}

# Block user account.
function block_account
{
    cls
    $block = Read-Host "Login: "`n
    Get-ADUser -Filter 'SamAccountName -like $block' | Disable-ADAccount
    $login_name = Get-ADUser -Filter 'SamAccountName -like $block' | Select-Object Name
    $who = Get-ADUser $env:USERNAME
    $date = Get-Date -Format "MM/dd/yyyy HH:mm"
    $log = "$($who.Name);$($login_name.Name);$date" | Out-File -FilePath $folder"blocked_accounts.txt" -Append
    a
}

# Change password.
function change_password
{
    cls
    $account = Read-Host "Login: "`n
    $password = Read-Host "New password: "`n
    $account1 = Get-ADUser -Filter 'SamAccountName -like $account'
    Set-ADAccountPassword -Identity $account1 -NewPassword (ConvertTo-SecureString -AsPlainText $password -Force)
    $login_name = Get-ADUser -Filter 'SamAccountName -like $account' | Select-Object Name
    $who = Get-ADUser $env:USERNAME
    $date = Get-Date -Format "MM/dd/yyyy HH:mm"
    $log = "$($who.Name);$($login_name.Name);$date" | Out-File -FilePath $folder"change_password.txt" -Append
    a
}

# Create group account.
function create_group
{
    cls
    $group = Read-Host "Group name: "`n
    $check = Get-ADGroup $group
    if($check)
    {
        Write-Host "This group alredy exists." -ForegroundColor Green
        Sleep 2
        b
    }
    else
    {
        New-ADGroup -Name:$group -SamAccountName:$group -GroupScope:"Global"
        $who = Get-ADUser $env:USERNAME 
        $date = Get-Date -Format "MM/dd/yyyy HH:mm"
        $log = "Creator Group Date" | ConvertFrom-String | Export-Csv -Path $folder"create_group.csv" -NoClobber -NoTypeInformation
        $log = "$($who.Name);$group;$date" | ConvertFrom-String -Delimiter ";" | Export-Csv -Path $folder"create_group.csv" -NoClobber -NoTypeInformation -Append
    }
    b
}

# Add user to group.
function add_to_group
{
    cls
    $group = Read-Host "Group name: "`n
    $check = Get-ADGroup $group
    if(!$check)
    {
        Write-Host "This group alredy exists." -ForegroundColor Red
        Sleep 2
        b
    }
    else
    {
        $user = Read-Host "Login: "`n
        $checkuser = Get-ADUser -Filter 'SamAccountName -like $user'
        if(!$checkuser)
        {
            Write-Host "This user alredy exists." -ForegroundColor Red
            Sleep 2
            b
        }
        else
        {
            Add-ADGroupMember -Identity $group -Members $user
            $who = Get-ADUser $env:USERNAME
            $log = "$($who.Name);$user;$group" | Out-File -FilePath $folder"group_membership.txt" -Append
        }
    }
    b
}

# Group list report.
function group_list
{
    Get-ADGroup -Filter * | Select-Object Name | % {
    $group = $_
    New-Item -Path $folder"$($group.Name).txt"
    Get-ADGroupMember $group.Name | Select-Object SamAccountName | Out-File -FilePath $folder"$($group.Name).txt"
    }
    c
}

# Blocked list report.
function list_blocked
{
    Get-ADUser -Filter {Enabled -eq $false} -properties WhenChanged | Select Name,DistinguishedName,SID,WhenChanged | Export-Csv -Path $folder"blocked_accounts.csv" -NoClobber -NoTypeInformation
    c
}

# Accounts list report.
function list_accounts
{
    Get-ADUser -Filter * -Properties whenCreated,whenChanged,LastLogonDate,PasswordLastSet | Select GivenName,Surname,UserPrincipalName,SamAccountName,DistinguishedName,whenCreated,whenChanged,LastLogonDate,PasswordLastSet | Export-Csv -Path $folder"users.csv" -NoClobber -NoTypeInformation
    c
}

# Computers list report.
function list_compusters
{
    Get-ADComputer -Filter * -Properties Enabled,PasswordLastSet,whenCreated,OperatingSystem | % {
    $computers = $_
    $computers | Select Name,SID,DistinguishedName,Enabled,PasswordLastSet,whenCreated | Export-Csv -Path $folder"$($computers.DNSHostName)_$($computers.OpeatingSystem).csv" -NoClobber -NoTypeInformation
    }
    c
}

# Organizational Unit list report.
function list_ou
{
    Get-ADOrganizationalUnit -Filter * -Properties Name,DistinguishedName | Select Name,DistinguishedName | Export-Csv -Path $folder"OU.csv" -NoClobber -NoTypeInformation
    c
}

cls # Clear console.
folder # Create destination folder.
menu # Run menu.
