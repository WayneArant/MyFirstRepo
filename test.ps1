# Multithreaded RESTful Web Service in PowerShell — Corrected & Hardened
# Author: PowerShell Expert (revised)
# Description: A complete REST API server with multithreading support

# =========================
# Configuration
# =========================
$Config = @{
    Port        = 8080
    MaxThreads  = 10
    BaseUrl     = "http://localhost:8080/"
    LogFile     = "webservice.log"
    CorsOrigins = "*"                  # set to specific origins for production
    CorsMaxAge  = 86400                 # seconds (1 day)
}

# =========================
# In-memory data store (in production, use a proper database)
# =========================
$Global:DataStore = @{
    Users      = @{}
    NextUserId = 1
    Lock       = [System.Threading.ReaderWriterLockSlim]::new()
}

# Will hold the runspace pool; referenced by /api/health
$script:RunspacePool = $null
$script:ServerStart  = Get-Date
$script:Stopping     = $false

# =========================
# Logging
# =========================
function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR')][string]$Level = 'INFO'
    )
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "[$timestamp] [$Level] $Message"
    Write-Host $logEntry
    try {
        Add-Content -Path $Config.LogFile -Value $logEntry -Encoding UTF8
    } catch {
        Write-Host "[LOGGING ERROR] $_" -ForegroundColor Red
    }
}

# =========================
# Helpers: JSON (compat) & request body
# =========================
function ConvertTo-Hashtable {
    param([Parameter(ValueFromPipeline=$true)]$InputObject)
    process {
        if ($null -eq $InputObject) { return $null }
        if ($InputObject -is [hashtable]) { return $InputObject }
        if ($InputObject -is [System.Collections.IDictionary]) {
            $ht = @{}
            foreach ($k in $InputObject.Keys) { $ht[$k] = ConvertTo-Hashtable $InputObject[$k] }
            return $ht
        }
        if ($InputObject -is [System.Collections.IEnumerable] -and -not ($InputObject -is [string])) {
            $list = @()
            foreach ($i in $InputObject) { $list += ,(ConvertTo-Hashtable $i) }
            return $list
        }
        if ($InputObject.PSObject -and $InputObject.PSObject.Properties.Count) {
            $ht = @{}
            foreach ($p in $InputObject.PSObject.Properties) { $ht[$p.Name] = ConvertTo-Hashtable $p.Value }
            return $ht
        }
        return $InputObject
    }
}

function ConvertFrom-JsonCompat {
    param([Parameter(Mandatory)][string]$Json)
    if ($PSVersionTable.PSVersion.Major -ge 7) {
        return $Json | ConvertFrom-Json -AsHashtable
    } else {
        $obj = $Json | ConvertFrom-Json
        return ConvertTo-Hashtable $obj
    }
}

function Read-RequestBodyText {
    param([Parameter(Mandatory)][System.IO.Stream]$Stream)
    $reader = New-Object System.IO.StreamReader($Stream, [System.Text.Encoding]::UTF8, $true, 1024, $true)
    try { return $reader.ReadToEnd() } finally { $reader.Dispose() }
}

# =========================
# Thread-safe data operations
# =========================
function Get-AllUsers {
    $Global:DataStore.Lock.EnterReadLock()
    try { return $Global:DataStore.Users.Values | ForEach-Object { $_ } }
    finally { $Global:DataStore.Lock.ExitReadLock() }
}

function Get-User {
    param([int]$Id)
    $Global:DataStore.Lock.EnterReadLock()
    try { return $Global:DataStore.Users[$Id] }
    finally { $Global:DataStore.Lock.ExitReadLock() }
}

function Add-User {
    param([hashtable]$User)
    $Global:DataStore.Lock.EnterWriteLock()
    try {
        $id = $Global:DataStore.NextUserId++
        $User.Id = $id
        $User.CreatedAt = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        $Global:DataStore.Users[$id] = $User
        return $User
    } finally { $Global:DataStore.Lock.ExitWriteLock() }
}

function Update-User {
    param([int]$Id, [hashtable]$User)
    $Global:DataStore.Lock.EnterWriteLock()
    try {
        if ($Global:DataStore.Users.ContainsKey($Id)) {
            $existingUser = $Global:DataStore.Users[$Id]
            $User.Id = $Id
            $User.CreatedAt = $existingUser.CreatedAt
            $User.UpdatedAt = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            $Global:DataStore.Users[$Id] = $User
            return $User
        }
        return $null
    } finally { $Global:DataStore.Lock.ExitWriteLock() }
}

function Remove-User {
    param([int]$Id)
    $Global:DataStore.Lock.EnterWriteLock()
    try { return $Global:DataStore.Users.Remove($Id) }
    finally { $Global:DataStore.Lock.ExitWriteLock() }
}

# =========================
# HTTP Response helpers
# =========================
function Add-CorsHeaders {
    param([System.Net.HttpListenerResponse]$Response)
    $Response.AddHeader('Access-Control-Allow-Origin', $Config.CorsOrigins)
    $Response.AddHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
    $Response.AddHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization')
    $Response.AddHeader('Access-Control-Max-Age', [string]$Config.CorsMaxAge)
}

function Send-JsonResponse {
    param(
        [Parameter(Mandatory)][System.Net.HttpListenerResponse]$Response,
        [Parameter()][object]$Data,
        [int]$StatusCode = 200
    )
    try {
        $json = $Data | ConvertTo-Json -Depth 10
        $buffer = [System.Text.Encoding]::UTF8.GetBytes($json)
        $Response.StatusCode = $StatusCode
        $Response.ContentType = 'application/json'
        $Response.ContentLength64 = $buffer.Length
        $Response.OutputStream.Write($buffer, 0, $buffer.Length)
    } catch {
        Write-Log "JSON serialization/response error: $_" -Level ERROR
        try { $Response.StatusCode = 500 } catch {}
    } finally {
        try { $Response.Close() } catch {}
    }
}

function Send-EmptyResponse {
    param([System.Net.HttpListenerResponse]$Response, [int]$StatusCode = 204)
    try { $Response.StatusCode = $StatusCode } finally { try { $Response.Close() } catch {} }
}

function Send-ErrorResponse {
    param(
        [System.Net.HttpListenerResponse]$Response,
        [string]$Message,
        [int]$StatusCode = 400
    )
    $errorObj = @{ error = $Message; statusCode = $StatusCode }
    Send-JsonResponse -Response $Response -Data $errorObj -StatusCode $StatusCode
}

# =========================
# Request router
# =========================
function Invoke-RequestRouter {
    param([System.Net.HttpListenerContext]$Context)

    $request  = $Context.Request
    $response = $Context.Response
    $method   = $request.HttpMethod
    $url      = $request.Url.AbsolutePath

    Write-Log "Processing $method $url from $($request.RemoteEndPoint)"

    try {
        Add-CorsHeaders -Response $response
        if ($method -eq 'OPTIONS') {
            Send-EmptyResponse -Response $response -StatusCode 204
            return
        }

        switch -Regex ($url) {
            '^/api/users/?$' {
                switch ($method) {
                    'GET' {
                        $users = Get-AllUsers
                        Send-JsonResponse -Response $response -Data $users
                    }
                    'POST' {
                        $body = Read-RequestBodyText -Stream $request.InputStream
                        if ([string]::IsNullOrWhiteSpace($body)) {
                            Send-ErrorResponse -Response $response -Message 'Request body required' -StatusCode 400
                            break
                        }
                        $userData = ConvertFrom-JsonCompat -Json $body
                        if (-not $userData.Name -or -not $userData.Email) {
                            Send-ErrorResponse -Response $response -Message 'Name and Email are required' -StatusCode 400
                            break
                        }
                        $newUser = Add-User -User $userData
                        Send-JsonResponse -Response $response -Data $newUser -StatusCode 201
                    }
                    Default { Send-ErrorResponse -Response $response -Message 'Method not allowed' -StatusCode 405 }
                }
            }
            '^/api/users/(\d+)/?$' {
                $userId = [int]$Matches[1]
                switch ($method) {
                    'GET' {
                        $user = Get-User -Id $userId
                        if ($user) { Send-JsonResponse -Response $response -Data $user }
                        else { Send-ErrorResponse -Response $response -Message 'User not found' -StatusCode 404 }
                    }
                    'PUT' {
                        $body = Read-RequestBodyText -Stream $request.InputStream
                        if ([string]::IsNullOrWhiteSpace($body)) {
                            Send-ErrorResponse -Response $response -Message 'Request body required' -StatusCode 400
                            break
                        }
                        $userData = ConvertFrom-JsonCompat -Json $body
                        $updatedUser = Update-User -Id $userId -User $userData
                        if ($updatedUser) { Send-JsonResponse -Response $response -Data $updatedUser }
                        else { Send-ErrorResponse -Response $response -Message 'User not found' -StatusCode 404 }
                    }
                    'DELETE' {
                        $removed = Remove-User -Id $userId
                        if ($removed) { Send-JsonResponse -Response $response -Data @{ message = 'User deleted successfully' } }
                        else { Send-ErrorResponse -Response $response -Message 'User not found' -StatusCode 404 }
                    }
                    Default { Send-ErrorResponse -Response $response -Message 'Method not allowed' -StatusCode 405 }
                }
            }
            '^/api/health/?$' {
                if ($method -eq 'GET') {
                    $available = if ($script:RunspacePool) { $script:RunspacePool.GetAvailableRunspaces() } else { $null }
                    $max       = if ($script:RunspacePool) { $script:RunspacePool.MaxRunspaces } else { $null }
                    $health = @{
                        status        = 'healthy'
                        timestamp     = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                        uptime        = ((Get-Date) - $script:ServerStart).ToString()
                        runspaces     = @{ available = $available; max = $max; active = if ($available -ne $null -and $max -ne $null) { $max - $available } else { $null } }
                        queuedJobs    = $script:Jobs.Count
                    }
                    Send-JsonResponse -Response $response -Data $health
                } else {
                    Send-ErrorResponse -Response $response -Message 'Method not allowed' -StatusCode 405
                }
            }
            Default { Send-ErrorResponse -Response $response -Message 'Endpoint not found' -StatusCode 404 }
        }
    }
    catch {
        Write-Log "Error processing request: $_" -Level 'ERROR'
        try { Send-ErrorResponse -Response $response -Message 'Internal server error' -StatusCode 500 } catch {}
    }
}

# =========================
# Runspace pool for multithreading
# =========================
$script:RunspacePool = [runspacefactory]::CreateRunspacePool(1, $Config.MaxThreads)
$script:RunspacePool.Open()

# =========================
# Job tracking (use ConcurrentQueue so we can dequeue safely)
# =========================
$script:Jobs = [System.Collections.Concurrent.ConcurrentQueue[PSCustomObject]]::new()

# =========================
# Request handler scriptblock (invoked within runspaces)
# =========================
$RequestHandler = {
    param($Context, $RouterFunction)
    try { & $RouterFunction -Context $Context }
    catch { Write-Error "Request handler error: $_" }
}

# =========================
# Main server function
# =========================
function Start-RestServer {
    Write-Log "Starting RESTful Web Service on $($Config.BaseUrl)"
    $script:ServerStart = Get-Date

    # Initialize HTTP Listener
    $listener = [System.Net.HttpListener]::new()
    $listener.Prefixes.Add($Config.BaseUrl)
    $listener.Start()

    Write-Log "Server started successfully. Listening on $($Config.BaseUrl)"
    Write-Log 'Available endpoints:'
    Write-Log '  GET    /api/health      - Health check'
    Write-Log '  GET    /api/users       - Get all users'
    Write-Log '  POST   /api/users       - Create new user'
    Write-Log '  GET    /api/users/{id}  - Get user by ID'
    Write-Log '  PUT    /api/users/{id}  - Update user by ID'
    Write-Log '  DELETE /api/users/{id}  - Delete user by ID'
    Write-Log ''
    Write-Log 'Press Ctrl+C to stop the server'

    # Graceful Ctrl+C shutdown
    $cancelSub = Register-EngineEvent -SourceIdentifier ConsoleCancelEvent -Action {
        $script:Stopping = $true
        Write-Log 'Ctrl+C received — initiating shutdown...'
    }

    # Cleanup completed jobs periodically
    $cleanupTimer = [System.Timers.Timer]::new(30000) # 30 seconds
    $cleanupTimer.AutoReset = $true
    $cleanupTimer.Add_Elapsed({
        try {
            # Drain and requeue incomplete jobs
            $count = $script:Jobs.Count
            for ($i=0; $i -lt $count; $i++) {
                $job = $null
                if ($script:Jobs.TryDequeue([ref]$job)) {
                    if ($null -ne $job) {
                        if ($job.AsyncResult.IsCompleted) {
                            try { $job.PowerShell.EndInvoke($job.AsyncResult) } catch {}
                            try { $job.PowerShell.Dispose() } catch {}
                        } else {
                            # Not finished — put it back
                            $script:Jobs.Enqueue($job)
                        }
                    }
                }
            }
        } catch {
            Write-Log "Cleanup error: $_" -Level 'ERROR'
        }
    })
    $cleanupTimer.Start()

    try {
        while ($listener.IsListening -and -not $script:Stopping) {
            # Get request context asynchronously with timeout
            $contextTask = $listener.GetContextAsync()
            if ($contextTask.Wait(1000)) {
                $context = $contextTask.Result

                # Create a new PowerShell instance for this request
                $ps = [PowerShell]::Create()
                $ps.RunspacePool = $script:RunspacePool

                # Inject the request handler and its arguments
                $null = $ps.AddScript($RequestHandler.ToString())
                $null = $ps.AddArgument($context)
                $null = $ps.AddArgument(${function:Invoke-RequestRouter})

                # Execute asynchronously
                $asyncResult = $ps.BeginInvoke()

                # Track the job
                $job = [PSCustomObject]@{
                    PowerShell  = $ps
                    AsyncResult = $asyncResult
                    StartTime   = Get-Date
                }
                $script:Jobs.Enqueue($job)
            }
        }
    }
    catch {
        Write-Log "Server error: $_" -Level 'ERROR'
    }
    finally {
        Write-Log 'Shutting down server...'
        try { $cleanupTimer.Stop(); $cleanupTimer.Dispose() } catch {}
        try { $listener.Stop() } catch {}

        # Finish running jobs
        Write-Log 'Waiting for active requests to complete...'
        while ($script:Jobs.TryDequeue([ref]$job)) {
            try {
                if (-not $job.AsyncResult.IsCompleted) { $job.PowerShell.EndInvoke($job.AsyncResult) }
            } catch {}
            finally { try { $job.PowerShell.Dispose() } catch {} }
        }

        try { $script:RunspacePool.Close(); $script:RunspacePool.Dispose() } catch {}
        try { $Global:DataStore.Lock.Dispose() } catch {}
        try { if ($cancelSub) { Unregister-Event -SubscriptionId $cancelSub.Id } } catch {}

        Write-Log 'Server shutdown complete'
    }
}

# =========================
# Example usage and testing functions
# =========================
function Test-RestService {
    Write-Host 'Testing REST Service endpoints...' -ForegroundColor Green

    # Test health endpoint
    try {
        $health = Invoke-RestMethod -Uri 'http://localhost:8080/api/health' -Method GET
        Write-Host "Health check: $($health.status)" -ForegroundColor Green
    }
    catch { Write-Host "Health check failed: $_" -ForegroundColor Red }

    # Test creating a user and fetch
    try {
        $newUser    = @{ Name = 'John Doe'; Email = 'john@example.com'; Age = 30 }
        $created    = Invoke-RestMethod -Uri 'http://localhost:8080/api/users' -Method POST -Body ($newUser | ConvertTo-Json) -ContentType 'application/json'
        Write-Host "Created user: $($created.Name) (ID: $($created.Id))" -ForegroundColor Green

        $retrieved  = Invoke-RestMethod -Uri "http://localhost:8080/api/users/$($created.Id)" -Method GET
        Write-Host "Retrieved user: $($retrieved.Name)" -ForegroundColor Green

        $allUsers   = Invoke-RestMethod -Uri 'http://localhost:8080/api/users' -Method GET
        Write-Host "Total users: $($allUsers.Count)" -ForegroundColor Green
    }
    catch { Write-Host "User operations failed: $_" -ForegroundColor Red }
}

# =========================
# Main execution
# =========================
if ($MyInvocation.InvocationName -ne '.') {
    # Add sample data
    Add-User -User @{ Name = 'Alice Smith'; Email = 'alice@example.com'; Age = 28; Role = 'Admin' }
    Add-User -User @{ Name = 'Bob Johnson';  Email = 'bob@example.com';  Age = 32; Role = 'User'  }

    # Start the server
    Start-RestServer
}
