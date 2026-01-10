Write-Host "[BNVD] Universal Installer"

if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
  Write-Host "[BNVD] Installing Winget"
  Invoke-WebRequest https://aka.ms/getwinget -OutFile winget.msixbundle
  Add-AppxPackage winget.msixbundle
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  Write-Host "[BNVD] Installing Docker Desktop"
  winget install -e --id Docker.DockerDesktop
}

docker pull azurejoga/bnvd:dev

docker rm -f bnvd-app-test 2>$null
docker run -d --name bnvd-app-test -p 4448:4448 azurejoga/bnvd:dev

Start-Sleep -Seconds 60

try {
  Invoke-WebRequest http://localhost:4448 -UseBasicParsing | Out-Null
  Write-Host "[BNVD] BNVD is running successfully"
} catch {
  Write-Host "[BNVD] Startup failed. Logs:"
  docker logs bnvd-app-test
}
