# visualizer.py

def display_network_data(network_data):
    """
    Ağ verilerini kullanıcıya ekrana yazdırır.

    :param network_data: Ağ verilerini içeren liste
    """
    if not network_data:
        print("No network data found.")
        return
    
    print("Source IP Address\tProtocol")
    print("-" * 50)
    
    for ip, protocol in network_data:
        print(f"{ip}\t{protocol}")
