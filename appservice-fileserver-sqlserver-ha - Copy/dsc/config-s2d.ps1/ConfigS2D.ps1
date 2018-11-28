
configuration ConfigS2D
{
    param
    (
        [Parameter(Mandatory)]
        [String]$DomainName,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$Admincreds,

        [Parameter(Mandatory)]
        [String]$ClusterName,

        [Parameter(Mandatory)]
        [String]$SOFSName,

        [Parameter(Mandatory)]
        [String]$ShareName,

        [Parameter(Mandatory)]
        [String]$vmNamePrefix,

        [Parameter(Mandatory)]
        [Int]$vmCount,

        [Parameter(Mandatory)]
        [Int]$vmDiskSize,

        [Parameter(Mandatory)]
        [String]$witnessStorageName,

        [Parameter(Mandatory)]
        [String]$witnessStorageEndpoint,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$witnessStorageKey,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$fileShareOwnerCreds,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$fileShareUserCreds,

        [String]$DomainNetbiosName=(Get-NetBIOSName -DomainName $DomainName),

        [Int]$RetryCount=20,
        [Int]$RetryIntervalSec=30

    )

    Import-DscResource -ModuleName xComputerManagement, xFailOverCluster, xActiveDirectory, xSOFS, cNtfsAccessControl
 
    [System.Management.Automation.PSCredential]$DomainCreds = New-Object System.Management.Automation.PSCredential ("${DomainNetbiosName}\$($Admincreds.UserName)", $Admincreds.Password)
    [System.Management.Automation.PSCredential]$DomainFQDNCreds = New-Object System.Management.Automation.PSCredential ("${DomainName}\$($Admincreds.UserName)", $Admincreds.Password)
    

    [System.Collections.ArrayList]$Nodes=@()
    For ($count=0; $count -lt $vmCount; $count++) {
        $Nodes.Add($vmNamePrefix + $Count.ToString())
    }

    Node localhost
    {

        WindowsFeature FC
        {
            Name = "Failover-Clustering"
            Ensure = "Present"
        }
<#
		WindowsFeature FailoverClusterTools 
        { 
            Ensure = "Present" 
            Name = "RSAT-Clustering-Mgmt"
			DependsOn = "[WindowsFeature]FC"
        } 
#>
        WindowsFeature FCPS
        {
            Name = "RSAT-Clustering-PowerShell"
            Ensure = "Present"
        }

        WindowsFeature ADPS
        {
            Name = "RSAT-AD-PowerShell"
            Ensure = "Present"
        }

        WindowsFeature FS
        {
            Name = "FS-FileServer"
            Ensure = "Present"
        }

        xWaitForADDomain DscForestWait 
        { 
            DomainName = $DomainName 
            DomainUserCredential= $DomainCreds
            RetryCount = $RetryCount 
            RetryIntervalSec = $RetryIntervalSec 
	        DependsOn = "[WindowsFeature]ADPS"
        }

        xComputer DomainJoin
        {
            Name = $env:COMPUTERNAME
            DomainName = $DomainName
            Credential = $DomainCreds
	        DependsOn = "[xWaitForADDomain]DscForestWait"
        }

        xADUser CreateFileShareOwnerAccount
        {
            DomainAdministratorCredential = $DomainCreds
            DomainName = $DomainName
            UserName = $fileShareOwnerCreds.UserName
            Password = $fileShareOwnerCreds
            PasswordNeverExpires = $true
            CannotChangePassword = $true
            Ensure = "Present"
            DependsOn = "[xComputer]DomainJoin"
        }

        xADUser CreateFileShareUserAccount
        {
            DomainAdministratorCredential = $DomainCreds
            DomainName = $DomainName
            UserName = $fileShareUserCreds.UserName
            Password = $fileShareUserCreds
            PasswordNeverExpires = $true
            CannotChangePassword = $true
            Ensure = "Present" 
            DependsOn = "[xADUser]CreateFileShareOwnerAccount"
        }

        xADGroup CreateFileShareOwnerGroup
        {
            Credential = $DomainCreds
            GroupName = 'FileShareOwners'
            GroupScope = 'Global'
            Category = 'Security'
            Members = @($fileShareOwnerCreds.UserName)
            Ensure = "Present"
            DependsOn = "[xADUser]CreateFileShareUserAccount"
        }

        xADGroup CreateFileShareUserGroup
        {
            Credential = $DomainCreds
            GroupName = 'FileShareUsers'
            GroupScope = 'Global'
            Category = 'Security'
            Members = @($fileShareUserCreds.UserName)
            Ensure = "Present"
            DependsOn = "[xADGroup]CreateFileShareOwnerGroup"          
        }


        xCluster FailoverCluster
        {
            Name = $ClusterName
            DomainAdministratorCredential = $DomainCreds
            Nodes = $Nodes
	        DependsOn = "[xADGroup]CreateFileShareUserGroup"
        }

        Script CloudWitness
        {
            SetScript = "Set-ClusterQuorum -CloudWitness -AccountName ${witnessStorageName} -AccessKey $($witnessStorageKey.GetNetworkCredential().Password) -Endpoint ${witnessStorageEndpoint}"
            TestScript = "(Get-ClusterQuorum).QuorumResource.Name -eq 'Cloud Witness'"
            GetScript = "@{Result = if ((Get-ClusterQuorum).QuorumResource.Name -eq 'Cloud Witness') {'Present'} else {'Absent'}}"
            DependsOn = "[xCluster]FailoverCluster"
        }

        Script IncreaseClusterTimeouts
        {
            SetScript = "(Get-Cluster).SameSubnetDelay = 2000; (Get-Cluster).SameSubnetThreshold = 15; (Get-Cluster).CrossSubnetDelay = 3000; (Get-Cluster).CrossSubnetThreshold = 15"
            TestScript = "(Get-Cluster).SameSubnetDelay -eq 2000 -and (Get-Cluster).SameSubnetThreshold -eq 15 -and (Get-Cluster).CrossSubnetDelay -eq 3000 -and (Get-Cluster).CrossSubnetThreshold -eq 15"
            GetScript = "@{Result = if ((Get-Cluster).SameSubnetDelay -eq 2000 -and (Get-Cluster).SameSubnetThreshold -eq 15 -and (Get-Cluster).CrossSubnetDelay -eq 3000 -and (Get-Cluster).CrossSubnetThreshold -eq 15) {'Present'} else {'Absent'}}"
            DependsOn = "[Script]CloudWitness"
        }

        Script EnableS2D
        {
            SetScript = "Enable-ClusterS2D -Confirm:0; New-Volume -StoragePoolFriendlyName S2D* -FriendlyName VDisk01 -FileSystem CSVFS_REFS -UseMaximumSize"
            TestScript = "(Get-ClusterSharedVolume).State -eq 'Online'"
            GetScript = "@{Result = if ((Get-ClusterSharedVolume).State -eq 'Online') {'Present'} Else {'Absent'}}"
            DependsOn = "[Script]IncreaseClusterTimeouts"
        }

        xSOFS EnableSOFS
        {
            SOFSName = $SOFSName
            DomainAdministratorCredential = $DomainCreds
            DependsOn = "[Script]EnableS2D"
        }
    
        File ShareDirectory
        {
            Ensure = 'Present'
            DestinationPath = "C:\ClusterStorage\Volume1\$ShareName"
            Type = 'Directory'
            DependsOn ="[xADGroup]CreateFileShareUserGroup"
        }
        
        Script CreateShare
        {
            SetScript = "New-SmbShare -Name ${ShareName} -Path C:\ClusterStorage\Volume1\${ShareName} -FullAccess Everyone"
            TestScript = "(Get-SmbShare -Name ${ShareName} -ErrorAction SilentlyContinue).ShareState -eq 'Online'"
            GetScript = "@{Result = if ((Get-SmbShare -Name ${ShareName} -ErrorAction SilentlyContinue).ShareState -eq 'Online') {'Present'} Else {'Absent'}}"
            DependsOn = "[File]ShareDirectory"
            Credential = $DomainCreds
        }

        cNtfsPermissionEntry AdminPermission
        {
            Ensure = 'Present'
            Path = "C:\ClusterStorage\Volume1\$ShareName"
            Principal = "Administrators"
            AccessControlInformation = @(
                cNtfsAccessControlInformation
                {
                    AccessControlType = 'Allow'
                    FileSystemRights = 'FullControl'
                    Inheritance = 'ThisFolderSubfoldersAndFiles'
                }
            )
            DependsOn = '[Script]CreateShare'
        }        
        cNtfsPermissionEntry OwnerPermission
        {
            Ensure = 'Present'
            Path = "C:\ClusterStorage\Volume1\$ShareName"
            Principal = "$DomainNetbiosName\FileShareOwners"
            AccessControlInformation = @(
                cNtfsAccessControlInformation
                {
                    AccessControlType = 'Allow'
                    FileSystemRights = 'Modify'
                    Inheritance = 'ThisFolderSubfoldersAndFiles'
                }
            )
            DependsOn = '[cNtfsPermissionEntry]AdminPermission'
        }

        cNtfsPermissionsInheritance DisableInheritance
        {
            Path = "C:\ClusterStorage\Volume1\$ShareName"
            Enabled = $false
            PreserveInherited = $false
            DependsOn = '[cNtfsPermissionEntry]OwnerPermission'
        }

        cNtfsPermissionEntry UserPermission
        {
            Ensure = 'Present'
            Path = "C:\ClusterStorage\Volume1\$ShareName"
            Principal = "$DomainNetbiosName\FileShareUsers"
            AccessControlInformation = @(
                cNtfsAccessControlInformation
                {
                    AccessControlType = 'Allow'
                    FileSystemRights = 'ReadAttributes,Synchronize,Traverse'
                    Inheritance = 'ThisFolderAndSubfolders'
                }
            )
            DependsOn = '[cNtfsPermissionsInheritance]DisableInheritance'
        }

        cNtfsPermissionEntry EveryonePermission
        {
            Ensure = 'Present'
            Path = "C:\ClusterStorage\Volume1\$ShareName"
            Principal = "S-1-1-0"
            AccessControlInformation = @(
                cNtfsAccessControlInformation
                {
                    AccessControlType = 'Allow'
                    FileSystemRights = 'ReadAttributes,ReadExtendedAttributes,ReadData'
                    Inheritance = 'SubfoldersAndFilesOnly'
                }
            )
            DependsOn = '[cNtfsPermissionEntry]UserPermission'
        }

        LocalConfigurationManager
        {
            RebootNodeIfNeeded = $true
        }

    }

}

function Get-NetBIOSName
{ 
    [OutputType([string])]
    param(
        [string]$DomainName
    )

    if ($DomainName.Contains('.')) {
        $length=$DomainName.IndexOf('.')
        if ( $length -ge 16) {
            $length=15
        }
        return $DomainName.Substring(0,$length)
    }
    else {
        if ($DomainName.Length -gt 15) {
            return $DomainName.Substring(0,15)
        }
        else {
            return $DomainName
        }
    }
}