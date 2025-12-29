# --- 6.7 Spoof Prevention ---
# Bật chống giả mạo IP trên vùng LAN và DMZ
FIX_SPOOF = """
<SpoofPrevention>
    <SpoofPrevention>Enable</SpoofPrevention>
    <IPSpoofing>
        <EnableOnZone>
            <Zone>DMZ</Zone>
            <Zone>LAN</Zone>
        </EnableOnZone>
    </IPSpoofing>
</SpoofPrevention>
"""

# --- 6.7 DoS Settings ---
# Bật cờ bảo vệ cho tất cả các loại Flood (SYN, UDP, TCP, ICMP) 
# và các tính năng phụ trợ (Source Routing, ICMP Redirect, ARP)
FIX_DOS = """
<DoSSettings>
    <SYNFlood>
        <Source><ApplyFlag>Enable</ApplyFlag></Source>
        <Destination><ApplyFlag>Enable</ApplyFlag></Destination>
    </SYNFlood>
    <UDPFlood>
        <Source><ApplyFlag>Enable</ApplyFlag></Source>
        <Destination><ApplyFlag>Enable</ApplyFlag></Destination>
    </UDPFlood>
    <TCPFlood>
        <Source><ApplyFlag>Enable</ApplyFlag></Source>
        <Destination><ApplyFlag>Enable</ApplyFlag></Destination>
    </TCPFlood>
    <ICMPFlood>
        <Source><ApplyFlag>Enable</ApplyFlag></Source>
        <Destination><ApplyFlag>Enable</ApplyFlag></Destination>
    </ICMPFlood>
    <DroppedSourceRoutedPackets>
        <Destination><ApplyFlag>Enable</ApplyFlag></Destination>
    </DroppedSourceRoutedPackets>
    <DisableICMPRedirectPacket>
        <Destination><ApplyFlag>Enable</ApplyFlag></Destination>
    </DisableICMPRedirectPacket>
    <DisableARPFlooding>
        <Destination><ApplyFlag>Enable</ApplyFlag></Destination>
    </DisableARPFlooding>
</DoSSettings>
"""

def get_safe_bypass_payloads():
    """
    Tạo payload Bypass DoS.
    Sửa đổi: DestinationIPNetmask được đặt giống SourceIPNetmask để tránh lỗi 501.
    """
    trusted_networks = [
        "172.16.16.0/24",  # Mạng LAN Local
        "100.64.0.0/10"    # Mạng Tailscale VPN
    ]
    
    payloads = []
    for subnet in trusted_networks:
        # [QUAN TRỌNG] Destination để cùng subnet với Source
        # Điều này có nghĩa: "Bỏ qua kiểm tra DoS cho giao thông nội bộ trong dải mạng này"
        xml = f"""
        <DoSBypassRules>
            <IPFamily>IPv4</IPFamily>
            <SourceIPNetmask>{subnet}</SourceIPNetmask>
            <DestinationIPNetmask>{subnet}</DestinationIPNetmask>
            <Protocol>AllProtocol</Protocol>
            <SourcePort><Port>1:65535</Port></SourcePort>
            <DestinationPort><Port>1:65535</Port></DestinationPort>
        </DoSBypassRules>
        """
        payloads.append(xml)
        
    return payloads

# Payload ĐỘNG cho Wifi (Hàm sinh XML)
def get_wifi_fix_payload(name, ssid, zone):
    return f"""
    <WirelessNetworks>
        <Name>{name}</Name> 
        <SSID>{ssid}</SSID>
        <Zone>{zone}</Zone>
        <SecurityMode>WPA2Personal</SecurityMode>
        <Encryption>AES(secure)</Encryption>
        <ClientIsolation>Enabled</ClientIsolation>
        <TimeBasedAccess>Enabled</TimeBasedAccess>
        <Passphrase>DoAnTotNghiep@2025</Passphrase>
    </WirelessNetworks>
    """