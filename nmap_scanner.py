import nmap

nm = nmap.PortScanner()
#The target is a random IP number.
target = "42.31.38.124"
options = "-sV -sC scan_results"

nm.scan(target, arguments=options)

for host in nm.all_hosts():
    print("Host: %s (%s)" % (host, nm[host].hostname()))
    print("State: %s" % nm[host].state())
    for protocol in nm[host].all_protocols(): 
        print("Protocol: %s" % protocol)
        port_i = nm[host][protocol]
        for port, state in port_i.items():
            print("Print: %s\tState: %s" % (port, state))
