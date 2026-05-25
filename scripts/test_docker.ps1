# Test Docker build, container startup, healthcheck, and HTTP APIs.
Write-Host "Starting Agent Comm Platform Docker Compose..."
docker compose down -v
docker compose up --build -d

$maxRetries = 15
$retryIntervalSec = 2
$healthy = $false

for ($i = 1; $i -le $maxRetries; $i++) {
    try {
        $resp = Invoke-RestMethod -Uri "http://localhost:8080/healthz" -Method Get
        if ($resp.status -eq "ok") {
            $healthy = $true
            break
        }
    } catch {
        # Ignore and retry
    }
    Write-Host "Waiting for platform to start (retry $i/$maxRetries)..."
    Start-Sleep -Seconds $retryIntervalSec
}

if (-not $healthy) {
    Write-Error "Platform failed to start or did not pass health check."
    docker compose logs
    docker compose down -v
    exit 1
}
Write-Host "Platform is healthy!"

# 1. Test HTTP Registry API
Write-Host "Testing HTTP Registry API..."
$urn = "urn:hermes:agent:docker-test"
$peerID = "12D3KooWJszDummyDockerPeerID"

$regBody = @{
    urn = $urn
    peer_id = $peerID
    addrs = @("/ip4/127.0.0.1/tcp/45041")
    x25519_pubkey = "eDI1NTE5LXB1YmxpYy1rZXktMzItYnl0ZXMtbG9uZw==" # dummy base64 x25519
    timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
} | ConvertTo-Json

$regResp = Invoke-RestMethod -Uri "http://localhost:8080/api/v1/registry/register" -Method Post -Body $regBody -ContentType "application/json"
if ($regResp.ok -ne $true) {
    Write-Error "Failed to register URN."
    docker compose down -v
    exit 1
}
Write-Host "URN registered successfully!"

$resolveResp = Invoke-RestMethod -Uri "http://localhost:8080/api/v1/registry/resolve?urn=$urn" -Method Get
if ($resolveResp.found -ne $true -or $resolveResp.peer_id -ne $peerID) {
    Write-Error "Failed to resolve registered URN."
    docker compose down -v
    exit 1
}
Write-Host "URN resolved successfully!"

# 2. Test HTTP MQ API
Write-Host "Testing HTTP MQ API..."
$mqStoreBody = @{
    recipient_urn = $urn
    payload_proto = "" # empty byte array is valid empty protobuf
    expiry_unix = 0
} | ConvertTo-Json

$mqStoreResp = Invoke-RestMethod -Uri "http://localhost:8080/api/v1/mq/store" -Method Post -Body $mqStoreBody -ContentType "application/json"
if ($mqStoreResp.ok -ne $true -or -not $mqStoreResp.message_id) {
    Write-Error "Failed to store MQ envelope."
    docker compose down -v
    exit 1
}
$msgID = $mqStoreResp.message_id
Write-Host "MQ envelope stored successfully, ID: $msgID"

$mqRetrieveResp = Invoke-RestMethod -Uri "http://localhost:8080/api/v1/mq/retrieve" -Method Get -Headers @{ "X-URN" = $urn }
if ($mqRetrieveResp.count -lt 1) {
    Write-Error "Failed to retrieve stored MQ envelope."
    docker compose down -v
    exit 1
}
Write-Host "MQ envelope retrieved successfully!"

$mqAckBody = @{
    message_ids = @($msgID)
} | ConvertTo-Json

$mqAckResp = Invoke-RestMethod -Uri "http://localhost:8080/api/v1/mq/ack" -Method Post -Body $mqAckBody -ContentType "application/json"
if ($mqAckResp.ok -ne $true -or $mqAckResp.deleted -ne 1) {
    Write-Error "Failed to ack MQ envelope."
    docker compose down -v
    exit 1
}
Write-Host "MQ envelope acked successfully!"

# 3. Cleanup
Write-Host "Cleaning up docker compose..."
docker compose down -v
Write-Host "All Docker Integration Tests passed successfully!"
