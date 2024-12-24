# Define variables
$BaseUrl = "http://192.168.1.25:1501/rules/"
$DownloadDirectory = "C:\Program Files\Suricata\rules"

# Create the download directory if it doesn't exist
if (!(Test-Path -Path $DownloadDirectory)) {
    New-Item -ItemType Directory -Path $DownloadDirectory
}

# Function to download files
function Update-Rules {
    Write-Output "Starting download of .rules files from $BaseUrl..."
    try {
        # Get the HTML content
        $HtmlContent = Invoke-WebRequest -Uri $BaseUrl -UseBasicParsing

        # Parse links to .rules files
        $RuleFiles = $HtmlContent.Links | Where-Object { $_.href -match "\.rules$" }

        if ($RuleFiles.Count -eq 0) {
            Write-Output "No .rules files found at $BaseUrl."
            return
        }

        # Download each .rules file
        foreach ($File in $RuleFiles) {
            $FileName = $File.href
            $DownloadUrl = "$BaseUrl$FileName"
            $DestinationPath = Join-Path $DownloadDirectory $FileName

            Write-Output "Downloading $FileName to $DestinationPath..."
            # Overwrite file if it exists
            Invoke-WebRequest -Uri $DownloadUrl -OutFile $DestinationPath
        }

        Write-Output "Download completed."
    } catch {
        Write-Error "Error during file download: $_"
    }
}

# Execute the function
Update-Rules 
