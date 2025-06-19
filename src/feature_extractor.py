def extract_features(packet):
    return {
        'length': len(packet),
        'has_IP': int(packet.haslayer('IP')),
        'has_TCP': int(packet.haslayer('TCP')),
        'has_UDP': int(packet.haslayer('UDP')),
        'has_ICMP': int(packet.haslayer('ICMP')),
        'sport': packet.sport if hasattr(packet, 'sport') else 0,
        'dport': packet.dport if hasattr(packet, 'dport') else 0,
    }
