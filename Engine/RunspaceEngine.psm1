<#
.SYNOPSIS
    ADTierGuard - Runspace Engine Module
    
.DESCRIPTION
    High-performance parallel processing engine using PowerShell runspaces.
    Provides thread-safe operations for bulk AD processing with configurable
    throttling, error handling, and progress reporting.
    
.NOTES
    Author: ADTierGuard Project
    Version: 2.0.0
    License: MIT
#>

#region Module Configuration
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
#endregion

#region Runspace Pool Management

<#
.SYNOPSIS
    Creates a configured runspace pool for parallel processing.
#>
function New-RunspacePool {
    [CmdletBinding()]
    [OutputType([System.Management.Automation.Runspaces.RunspacePool])]
    param(
        [Parameter()]
        [ValidateRange(1, 64)]
        [int]$MinRunspaces = 1,
        
        [Parameter()]
        [ValidateRange(1, 64)]
        [int]$MaxRunspaces = [Environment]::ProcessorCount * 2,
        
        [Parameter()]
        [hashtable]$Variables = @{},
        
        [Parameter()]
        [string[]]$Modules = @(),
        
        [Parameter()]
        [System.Threading.ApartmentState]$ApartmentState = [System.Threading.ApartmentState]::MTA,
        
        [Parameter()]
        [System.Management.Automation.PSThreadOptions]$ThreadOptions = [System.Management.Automation.PSThreadOptions]::ReuseThread
    )
    
    try {
        # Create initial session state
        $sessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $sessionState.ApartmentState = $ApartmentState
        $sessionState.ThreadOptions = $ThreadOptions
        
        # Add variables to session state
        foreach ($key in $Variables.Keys) {
            $variableEntry = [System.Management.Automation.Runspaces.SessionStateVariableEntry]::new(
                $key, $Variables[$key], $null
            )
            $sessionState.Variables.Add($variableEntry)
        }
        
        # Import modules
        foreach ($module in $Modules) {
            if (Test-Path $module) {
                $sessionState.ImportPSModule($module)
            }
            else {
                Write-Warning "Module not found: $module"
            }
        }
        
        # Create runspace pool
        $runspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(
            $MinRunspaces, $MaxRunspaces, $sessionState, $Host
        )
        
        $runspacePool.Open()
        
        Write-Verbose "Created runspace pool with $MinRunspaces-$MaxRunspaces runspaces"
        return $runspacePool
    }
    catch {
        Write-Error "Failed to create runspace pool: $_"
        throw
    }
}

<#
.SYNOPSIS
    Closes and disposes of a runspace pool.
#>
function Close-RunspacePool {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Runspaces.RunspacePool]$RunspacePool,
        
        [Parameter()]
        [int]$TimeoutSeconds = 30
    )
    
    try {
        if ($RunspacePool.RunspacePoolStateInfo.State -eq 'Opened') {
            $RunspacePool.Close()
        }
        $RunspacePool.Dispose()
        Write-Verbose "Runspace pool closed and disposed"
    }
    catch {
        Write-Warning "Error closing runspace pool: $_"
    }
}
#endregion

#region Parallel Execution Framework

<#
.SYNOPSIS
    Represents the result of a parallel job execution.
#>
class ParallelJobResult {
    [string]$JobId
    [object]$InputObject
    [object]$Output
    [System.Management.Automation.ErrorRecord[]]$Errors
    [bool]$Success
    [TimeSpan]$Duration
    [DateTime]$StartTime
    [DateTime]$EndTime
    
    ParallelJobResult() {
        $this.Errors = @()
        $this.Success = $true
    }
}

<#
.SYNOPSIS
    Invokes a script block in parallel across multiple items.
#>
function Invoke-ParallelOperation {
    [CmdletBinding()]
    [OutputType([ParallelJobResult[]])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [object[]]$InputObjects,
        
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,
        
        [Parameter()]
        [ValidateRange(1, 64)]
        [int]$ThrottleLimit = [Environment]::ProcessorCount,
        
        [Parameter()]
        [hashtable]$ArgumentList = @{},
        
        [Parameter()]
        [string[]]$ModulesToImport = @(),
        
        [Parameter()]
        [int]$TimeoutSeconds = 300,
        
        [Parameter()]
        [switch]$ShowProgress,
        
        [Parameter()]
        [string]$ProgressActivity = 'Processing items'
    )
    
    begin {
        $allInputs = [System.Collections.Generic.List[object]]::new()
    }
    
    process {
        foreach ($item in $InputObjects) {
            $allInputs.Add($item)
        }
    }
    
    end {
        if ($allInputs.Count -eq 0) {
            return @()
        }
        
        $results = [System.Collections.Concurrent.ConcurrentBag[ParallelJobResult]]::new()
        $jobs = [System.Collections.Generic.List[hashtable]]::new()
        $runspacePool = $null
        
        try {
            # Create runspace pool
            $runspacePool = New-RunspacePool -MaxRunspaces $ThrottleLimit -Modules $ModulesToImport -Variables $ArgumentList
            
            $totalItems = $allInputs.Count
            $processedCount = 0
            
            # Create jobs for all items
            foreach ($input in $allInputs) {
                $powershell = [PowerShell]::Create()
                $powershell.RunspacePool = $runspacePool
                
                # Add script with input parameter
                [void]$powershell.AddScript({
                    param($InputItem, $UserScript, $UserArgs)
                    
                    $result = [PSCustomObject]@{
                        JobId       = [Guid]::NewGuid().ToString()
                        InputObject = $InputItem
                        Output      = $null
                        Errors      = @()
                        Success     = $true
                        StartTime   = [DateTime]::Now
                        EndTime     = $null
                    }
                    
                    try {
                        # Create script block from string if needed
                        $scriptToRun = if ($UserScript -is [scriptblock]) {
                            $UserScript
                        }
                        else {
                            [scriptblock]::Create($UserScript)
                        }
                        
                        # Execute with item as $_
                        $result.Output = $InputItem | ForEach-Object $scriptToRun
                    }
                    catch {
                        $result.Success = $false
                        $result.Errors = @($_)
                    }
                    finally {
                        $result.EndTime = [DateTime]::Now
                    }
                    
                    return $result
                })
                
                [void]$powershell.AddParameter('InputItem', $input)
                [void]$powershell.AddParameter('UserScript', $ScriptBlock.ToString())
                [void]$powershell.AddParameter('UserArgs', $ArgumentList)
                
                $asyncResult = $powershell.BeginInvoke()
                
                $jobs.Add(@{
                    PowerShell  = $powershell
                    AsyncResult = $asyncResult
                    Input       = $input
                    StartTime   = [DateTime]::Now
                })
            }
            
            # Collect results
            $completedJobs = [System.Collections.Generic.HashSet[int]]::new()
            $timeoutTime = [DateTime]::Now.AddSeconds($TimeoutSeconds)
            
            while ($completedJobs.Count -lt $jobs.Count -and [DateTime]::Now -lt $timeoutTime) {
                for ($i = 0; $i -lt $jobs.Count; $i++) {
                    if ($completedJobs.Contains($i)) {
                        continue
                    }
                    
                    $job = $jobs[$i]
                    
                    if ($job.AsyncResult.IsCompleted) {
                        [void]$completedJobs.Add($i)
                        $processedCount++
                        
                        try {
                            $output = $job.PowerShell.EndInvoke($job.AsyncResult)
                            
                            if ($output -and $output.Count -gt 0) {
                                $jobResult = [ParallelJobResult]::new()
                                $jobResult.JobId = $output[0].JobId
                                $jobResult.InputObject = $output[0].InputObject
                                $jobResult.Output = $output[0].Output
                                $jobResult.Success = $output[0].Success
                                $jobResult.StartTime = $output[0].StartTime
                                $jobResult.EndTime = $output[0].EndTime
                                $jobResult.Duration = $output[0].EndTime - $output[0].StartTime
                                
                                if ($output[0].Errors) {
                                    $jobResult.Errors = $output[0].Errors
                                }
                                
                                # Check for PowerShell stream errors
                                if ($job.PowerShell.Streams.Error.Count -gt 0) {
                                    $jobResult.Errors += $job.PowerShell.Streams.Error
                                    if (-not $output[0].Errors) {
                                        $jobResult.Success = $false
                                    }
                                }
                                
                                $results.Add($jobResult)
                            }
                        }
                        catch {
                            $jobResult = [ParallelJobResult]::new()
                            $jobResult.InputObject = $job.Input
                            $jobResult.Success = $false
                            $jobResult.Errors = @($_)
                            $jobResult.StartTime = $job.StartTime
                            $jobResult.EndTime = [DateTime]::Now
                            $jobResult.Duration = [DateTime]::Now - $job.StartTime
                            $results.Add($jobResult)
                        }
                        finally {
                            $job.PowerShell.Dispose()
                        }
                        
                        # Update progress
                        if ($ShowProgress) {
                            $percentComplete = [math]::Round(($processedCount / $totalItems) * 100)
                            Write-Progress -Activity $ProgressActivity `
                                -Status "Processing $processedCount of $totalItems" `
                                -PercentComplete $percentComplete
                        }
                    }
                }
                
                Start-Sleep -Milliseconds 100
            }
            
            # Handle timed out jobs
            for ($i = 0; $i -lt $jobs.Count; $i++) {
                if (-not $completedJobs.Contains($i)) {
                    $job = $jobs[$i]
                    $job.PowerShell.Stop()
                    
                    $jobResult = [ParallelJobResult]::new()
                    $jobResult.InputObject = $job.Input
                    $jobResult.Success = $false
                    $jobResult.Errors = @([System.Management.Automation.ErrorRecord]::new(
                        [TimeoutException]::new("Job exceeded timeout of $TimeoutSeconds seconds"),
                        'JobTimeout',
                        [System.Management.Automation.ErrorCategory]::OperationTimeout,
                        $job.Input
                    ))
                    $jobResult.StartTime = $job.StartTime
                    $jobResult.EndTime = [DateTime]::Now
                    $jobResult.Duration = [DateTime]::Now - $job.StartTime
                    $results.Add($jobResult)
                    
                    $job.PowerShell.Dispose()
                }
            }
            
            if ($ShowProgress) {
                Write-Progress -Activity $ProgressActivity -Completed
            }
            
            return @($results)
        }
        catch {
            Write-Error "Parallel execution failed: $_"
            throw
        }
        finally {
            if ($runspacePool) {
                Close-RunspacePool -RunspacePool $runspacePool
            }
        }
    }
}
#endregion

#region Batch Processing

<#
.SYNOPSIS
    Processes items in batches with parallel execution within each batch.
#>
function Invoke-BatchOperation {
    [CmdletBinding()]
    [OutputType([ParallelJobResult[]])]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$InputObjects,
        
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,
        
        [Parameter()]
        [ValidateRange(1, 1000)]
        [int]$BatchSize = 100,
        
        [Parameter()]
        [ValidateRange(1, 64)]
        [int]$ThrottleLimit = [Environment]::ProcessorCount,
        
        [Parameter()]
        [hashtable]$ArgumentList = @{},
        
        [Parameter()]
        [int]$DelayBetweenBatchesMs = 0,
        
        [Parameter()]
        [switch]$ShowProgress,
        
        [Parameter()]
        [string]$ProgressActivity = 'Batch processing'
    )
    
    $allResults = [System.Collections.Generic.List[ParallelJobResult]]::new()
    $totalItems = $InputObjects.Count
    $totalBatches = [math]::Ceiling($totalItems / $BatchSize)
    $currentBatch = 0
    
    for ($i = 0; $i -lt $totalItems; $i += $BatchSize) {
        $currentBatch++
        $batchEnd = [math]::Min($i + $BatchSize - 1, $totalItems - 1)
        $batch = $InputObjects[$i..$batchEnd]
        
        if ($ShowProgress) {
            $percentComplete = [math]::Round(($currentBatch / $totalBatches) * 100)
            Write-Progress -Activity $ProgressActivity `
                -Status "Batch $currentBatch of $totalBatches" `
                -PercentComplete $percentComplete
        }
        
        Write-Verbose "Processing batch $currentBatch of $totalBatches ($($batch.Count) items)"
        
        $batchResults = Invoke-ParallelOperation -InputObjects $batch `
            -ScriptBlock $ScriptBlock `
            -ThrottleLimit $ThrottleLimit `
            -ArgumentList $ArgumentList
        
        foreach ($result in $batchResults) {
            $allResults.Add($result)
        }
        
        if ($DelayBetweenBatchesMs -gt 0 -and $currentBatch -lt $totalBatches) {
            Start-Sleep -Milliseconds $DelayBetweenBatchesMs
        }
    }
    
    if ($ShowProgress) {
        Write-Progress -Activity $ProgressActivity -Completed
    }
    
    return $allResults.ToArray()
}
#endregion

#region Thread-Safe Collections

<#
.SYNOPSIS
    Creates a thread-safe dictionary for concurrent access.
#>
function New-ThreadSafeDictionary {
    [CmdletBinding()]
    [OutputType([System.Collections.Concurrent.ConcurrentDictionary[string, object]])]
    param()
    
    return [System.Collections.Concurrent.ConcurrentDictionary[string, object]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
}

<#
.SYNOPSIS
    Creates a thread-safe queue for producer-consumer patterns.
#>
function New-ThreadSafeQueue {
    [CmdletBinding()]
    [OutputType([System.Collections.Concurrent.ConcurrentQueue[object]])]
    param()
    
    return [System.Collections.Concurrent.ConcurrentQueue[object]]::new()
}

<#
.SYNOPSIS
    Creates a thread-safe collection bag.
#>
function New-ThreadSafeBag {
    [CmdletBinding()]
    [OutputType([System.Collections.Concurrent.ConcurrentBag[object]])]
    param()
    
    return [System.Collections.Concurrent.ConcurrentBag[object]]::new()
}
#endregion

#region Progress Tracking

<#
.SYNOPSIS
    Creates a progress tracker for parallel operations.
#>
class ProgressTracker {
    [int]$TotalItems
    [int]$ProcessedItems
    [int]$SuccessCount
    [int]$FailureCount
    [DateTime]$StartTime
    [string]$Activity
    hidden [object]$Lock
    
    ProgressTracker([int]$total, [string]$activity) {
        $this.TotalItems = $total
        $this.ProcessedItems = 0
        $this.SuccessCount = 0
        $this.FailureCount = 0
        $this.StartTime = [DateTime]::Now
        $this.Activity = $activity
        $this.Lock = [object]::new()
    }
    
    [void] IncrementSuccess() {
        [System.Threading.Monitor]::Enter($this.Lock)
        try {
            $this.ProcessedItems++
            $this.SuccessCount++
        }
        finally {
            [System.Threading.Monitor]::Exit($this.Lock)
        }
    }
    
    [void] IncrementFailure() {
        [System.Threading.Monitor]::Enter($this.Lock)
        try {
            $this.ProcessedItems++
            $this.FailureCount++
        }
        finally {
            [System.Threading.Monitor]::Exit($this.Lock)
        }
    }
    
    [double] GetPercentComplete() {
        if ($this.TotalItems -eq 0) { return 100 }
        return [math]::Round(($this.ProcessedItems / $this.TotalItems) * 100, 2)
    }
    
    [TimeSpan] GetElapsedTime() {
        return [DateTime]::Now - $this.StartTime
    }
    
    [TimeSpan] GetEstimatedTimeRemaining() {
        if ($this.ProcessedItems -eq 0) {
            return [TimeSpan]::MaxValue
        }
        $elapsed = $this.GetElapsedTime()
        $itemsPerSecond = $this.ProcessedItems / $elapsed.TotalSeconds
        $remainingItems = $this.TotalItems - $this.ProcessedItems
        return [TimeSpan]::FromSeconds($remainingItems / $itemsPerSecond)
    }
    
    [string] GetStatusMessage() {
        $pct = $this.GetPercentComplete()
        $eta = $this.GetEstimatedTimeRemaining()
        return "Processed $($this.ProcessedItems)/$($this.TotalItems) ($pct%) - Success: $($this.SuccessCount), Failed: $($this.FailureCount) - ETA: $($eta.ToString('hh\:mm\:ss'))"
    }
}

<#
.SYNOPSIS
    Creates a new progress tracker instance.
#>
function New-ProgressTracker {
    [CmdletBinding()]
    [OutputType([ProgressTracker])]
    param(
        [Parameter(Mandatory = $true)]
        [int]$TotalItems,
        
        [Parameter()]
        [string]$Activity = 'Processing'
    )
    
    return [ProgressTracker]::new($TotalItems, $Activity)
}
#endregion

#region Result Aggregation

<#
.SYNOPSIS
    Aggregates and summarizes parallel operation results.
#>
function Get-ParallelOperationSummary {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [ParallelJobResult[]]$Results
    )
    
    $successResults = @($Results | Where-Object { $_.Success })
    $failedResults = @($Results | Where-Object { -not $_.Success })
    
    $totalDuration = if ($Results.Count -gt 0) {
        ($Results | Measure-Object -Property Duration -Sum).Sum
    }
    else {
        [TimeSpan]::Zero
    }
    
    $averageDuration = if ($Results.Count -gt 0) {
        [TimeSpan]::FromTicks($totalDuration.Ticks / $Results.Count)
    }
    else {
        [TimeSpan]::Zero
    }
    
    return [PSCustomObject]@{
        TotalOperations   = $Results.Count
        SuccessCount      = $successResults.Count
        FailureCount      = $failedResults.Count
        SuccessRate       = if ($Results.Count -gt 0) { 
            [math]::Round(($successResults.Count / $Results.Count) * 100, 2) 
        } else { 0 }
        TotalDuration     = $totalDuration
        AverageDuration   = $averageDuration
        FailedItems       = $failedResults | ForEach-Object {
            [PSCustomObject]@{
                Input  = $_.InputObject
                Errors = $_.Errors | ForEach-Object { $_.Exception.Message }
            }
        }
        ErrorSummary      = $failedResults | ForEach-Object { $_.Errors } | 
            Group-Object { $_.Exception.GetType().Name } |
            ForEach-Object {
                [PSCustomObject]@{
                    ErrorType = $_.Name
                    Count     = $_.Count
                }
            }
    }
}
#endregion

#region Export Module Members
Export-ModuleMember -Function @(
    # Runspace Pool
    'New-RunspacePool'
    'Close-RunspacePool'
    
    # Parallel Execution
    'Invoke-ParallelOperation'
    'Invoke-BatchOperation'
    
    # Thread-Safe Collections
    'New-ThreadSafeDictionary'
    'New-ThreadSafeQueue'
    'New-ThreadSafeBag'
    
    # Progress
    'New-ProgressTracker'
    
    # Results
    'Get-ParallelOperationSummary'
)
#endregion
