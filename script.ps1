#Install-Module -Name Az -Repository PSGallery -Force -Scope CurrentUser -AllowClobber

#Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy Unrestricted

Log $(Connect-AzAccount)

Get-AzPublicIpAddress

function Log ($log) {
#test-path dodac
Add-Content -Path "C:\ASC\18547\LOG\data-log.txt" -Force -Value "$(Get-Date);$env:USERNAME;$log"
Write-Host $log
}

function Menu {
    # create vm from file
    # custom vm
        # create network
        # create storage
    # delete all
    # exit
}

function CreateVM {
New-AzResourceGroup -Name 18547 -Location eastus
#create resourcegroup
#create nsg
#create publicip
#create vm
#create networkinterface
#create disk
#create virtualnetwork
}

function DeleteAll {
$vmConfig = Get-AzVM -ResourceGroupName 18547 -Name sqlVM
$vmConfig.StorageProfile.OsDisk.DeleteOption = 'Delete'
$vmConfig.StorageProfile.DataDisks | ForEach-Object { $_.DeleteOption = 'Delete' }
$vmConfig.NetworkProfile.NetworkInterfaces | ForEach-Object { $_.DeleteOption = 'Delete' }
$vmConfig | Update-AzVM

Remove-AzVm `
    -ResourceGroupName "18547" `
    -Name "sqlVM" `
    -ForceDeletion $true

Remove-AzResourceGroup -Name 18547 -Force
}

function 1-CreateSQLServerVMFull {
    #uprszczony kod tworzacy VM-ke 

New-AzVm `
    -ResourceGroupName '18547' `
    -Name 'sqlVM' `
    -Location 'eastus' `
    -Image 'microsoftsqlserver:sql2022-ws2022:sqldev-gen2:latest' `
    -VirtualNetworkName 'sqlVnet' `
    -Size 'Standard_B1ms'`
    -SubnetName 'sqlSubnet' `
    -SecurityGroupName 'sqlNSG' `
    -PublicIpAddressName 'sqlPublicIP' `
    -OpenPorts 80,3389

}

function 2-CreateAppServerVMFull {
    #uprszczony kod tworzacy VM-ke 

New-AzVm `
    -ResourceGroupName '18547' `
    -Name 'appVM' `
    -Location 'eastus' `
    -Image 'MicrosoftWindowsServer:WindowsServer:2022-datacenter-azure-edition:latest' `
    -VirtualNetworkName 'appVnet' `
    -Size 'Standard_B1ms'`
    -SubnetName 'appSubnet' `
    -SecurityGroupName 'appNSG' `
    -PublicIpAddressName 'appPublicIP' `
    -OpenPorts 80,3389

Invoke-AzVmRunCommand `
     -ResourceGroupName "18547" `
     -VMName "appVM" `
     -CommandId "RunPowerShellScript" `
     -ScriptString "Install-WindowsFeature -Name Web-Server -IncludeManagementTools"

Invoke-AzVmRunCommand `
     -ResourceGroupName "18547" `
     -VMName "appVM" `
     -CommandId "RunPowerShellScript" `
     -ScriptString "Set-Content -Path 'C:\inetpub\wwwroot\iisstart.htm' -Value 'imie nazwisko praca zaliczeniowa asc'"

Invoke-AzVmRunCommand `
     -ResourceGroupName "18547" `
     -VMName "appVM" `
     -CommandId "RunPowerShellScript" `
     -ScriptString "Start-IISSite -Name 'Default Web Site'"

Invoke-AzVmRunCommand `
     -ResourceGroupName "18547" `
     -VMName "appVM" `
     -CommandId "RunPowerShellScript" `
     -ScriptString "Start-Process 'http://localhost:80'"
}

############## 

#Podpis: Bartłomeij Sztejn, 18547 

############## 



############## 

#Zmienne 

############## 



############## 

#Funkcje 

##############


function get-location {
    $choice = Read-Host -Prompt "Choose from avaiable locations: `n$($regions)`n"
    [string]$location = ""
    switch ($choice)
    {
        $regions[0] {
        Write-Host "You chose $($regions[0])"
        $location = $choice
        }
        $regions[1] {
        Write-Host "You chose $($regions[1])"
        $location = $choice
        }
        default {
        Write-Host "Wrong location!" -ForegroundColor Red
        get-location
        }
    }
    return [string]$location
}

function get-rgname {
    $rgName = Read-Host -Prompt "Resource Group name: `n"
    if(Get-AzResourceGroup -Name $rgName 2>null) {
        Write-Host "Resource group $($name) alredy exists!" -ForegroundColor Red
        get-rgname
    }
    else {
        return [string]$rgName
    }
}

function get-tags {
    do {
        $key = Read-Host -Prompt "Tag Name: `n"
        $val = Read-Host -Prompt "Tag Value: `n"
        $tags.Add($key,$val)
        $flag = Read-Host -Prompt "Add more tags? (y/n): `n"
    } while($flag -ne 'n')
    return $tags
}

function create-rg {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$name,
        [Parameter(Mandatory)]
        [string]$location,
        [Parameter(Mandatory)]
        [Hashtable]$tags
    )
    New-AzResourceGroup -Name $name -Location $location -Tag $tags
}

function main {
    Connect-AzAccount
    [string]$location = get-location
    [string]$rgname = get-rgname
    $tags = get-tags
    create-rg -name $rgname -location $location -tags $tags
}

############## 

#Blok skryptu 

############## 



############## 

#Skrypt end

##############