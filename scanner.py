import nmap

def escanear_host(ip):
    escaner = nmap.PortScanner()
    try:
        escaner.scan(ip, arguments='-O -sV')
        return escaner[ip] if ip in escaner.all_hosts() else None
    except Exception as e:
        return f"Error en escaneo: {e}"
