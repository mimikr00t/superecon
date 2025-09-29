def is_core_running():
    """More reliable process checking"""
    try:
        # Check if our process is running
        result = subprocess.run("pgrep -f 'python3.*networkd'", 
                              shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            # Verify it's actually connected
            netstat_result = subprocess.run("netstat -tunp 2>/dev/null | grep 4444", 
                                          shell=True, capture_output=True, text=True)
            return "ESTABLISHED" in netstat_result.stdout
        return False
    except:
        return False
