#regex:
# ^[\w-]+ \| User: [^\s\\|]+\\[^\s\\|]+ \| RAM: \d+(?:\.\d+)? GB free / \d+(?:\.\d+)? GB total \(\d+(?:\.\d+)?% free\)\r?$
# reverse ^(?![\w-]+ \| User: [^\s\\|]+\\[^\s\\|]+ \| RAM: \d+(?:\.\d+)? GB free / \d+(?:\.\d+)? GB total \(\d+(?:\.\d+)?% free\)\r?$)[^\r\n]*(?:\r?\n|$)
#regex=========================

$os   = Get-CimInstance Win32_OperatingSystem
$user = (Get-CimInstance Win32_ComputerSystem).UserName
$free = $os.FreePhysicalMemory / 1MB
$total = $os.TotalVisibleMemorySize / 1MB

"{0} | User: {1} | RAM: {2:N2} GB free / {3:N2} GB total ({4:N1}% free)" -f `
    $env:COMPUTERNAME, $user, $free, $total, ($free / $total * 100)