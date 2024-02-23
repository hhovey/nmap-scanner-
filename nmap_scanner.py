import nmap

nm = nmap.PortScanner()

target = "45.36.31.154"
options = "-sV -sC scan_results"

nm.scan(target, arguments=options)

for host in nm.all_hosts():
    print("Host: %s (%s)" % (host, nm[host].hostname()))
    print("State: %s" % nm[host].state())
    for protocol in nm[host].all_protocols(): 
        print("Protocol: %s" % protocol)
        port_info = nm[host][protocol]
        for port, state in port_info.items():
            print("Print: %s\tState: %s" % (port, state))