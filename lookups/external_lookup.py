# An aadapter that takes CSV as input, performs a lookup to some external system, then returns the CSV results
import csv,sys,commands,socket

# Given a host, find the ip
def lookup(host):
    try:
        hostname, aliaslist, ipaddrlist = socket.gethostbyname_ex(host)
        return ipaddrlist
    except:
        return []

# Given an ip, return the host
def rlookup(ip):
    try:
        hostname, aliaslist, ipaddrlist = socket.gethostbyaddr(ip)
        return hostname
    except:
        return ''

def main():
    if len(sys.argv) != 3:
        print "Usage: python external_lookup.py [host field] [ip field]"
        sys.exit(0)

    hostf = sys.argv[1]
    ipf = sys.argv[2]
    r = csv.reader(sys.stdin)
    w = None
    header = []
    first = True

    for line in r:
        if first:
            header = line
            if hostf not in header or ipf not in header:
                print "Host and IP fields must exist in CSV data"
                sys.exit(0)
            csv.writer(sys.stdout).writerow(header)
            w = csv.DictWriter(sys.stdout, header)
            first = False
            continue

        # Read the result
        result = {}
        i = 0
        while i < len(header):
            if i < len(line):
                result[header[i]] = line[i]
            else:
                result[header[i]] = ''
            i += 1

        # Perform the lookup or reverse lookup if necessary
        if len(result[hostf]) and len(result[ipf]):
            w.writerow(result)

        elif len(result[hostf]):
            ips = lookup(result[hostf])
            for ip in ips:
                result[ipf] = ip
                w.writerow(result)

        elif len(result[ipf]):
            result[hostf] = rlookup(result[ipf])
            if len(result[hostf]):
                w.writerow(result)

main()
