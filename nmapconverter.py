import xmltodict
import sys

# XML Processing
def printtree(n, blob):
	if type(blob) == str:
		print("\t"*n, blob)
	elif type(blob) == list:
		for k in blob:
			printtree(n+1, k)
	elif type(blob) != type(None):
		for k in blob:
			print("\t"*n, k)
			printtree(n+1, blob[k])

def getorraise(document, list):
	element = document
	for value in list:
		temp = []
		if type(element) == type(list):
			for elem in element:
				print(type(elem))
				if value in elem:
					temp.append(elem[value])
		else:
			if value in element:
				temp.append(element[value])
		if len(temp) == 0:
			raise Exception("Expected '{}' in document.".format("/".join(list)))
		elif len(temp) == 1:
			element = temp[0]
		else:
			element = temp
	return element

# GNMAP routines
def xmltognmap(document):
	gnmapdocument = getgnmapheader(document) + "\n"
	for host in gethostlist(document):
		gnmapdocument = gnmapdocument + getgnmaphost(host) + "\n"
	gnmapdocument = gnmapdocument + getgnmapfooter(document)
	return gnmapdocument

def getgnmapheader(document):
	version =  getorraise(document, ['nmaprun','@version'])
	startstr = getorraise(document, ['nmaprun','@startstr'])
	args =	   getorraise(document, ['nmaprun','@args'])
	return "# Nmap {} scan initiated {} as: {}".format(version, startstr, args)

def getgnmapfooter(document):
	timestr = getorraise(document, ['nmaprun','runstats','finished','@timestr'])
	total =   getorraise(document, ['nmaprun','runstats','hosts','@total'])
	up =      getorraise(document, ['nmaprun','runstats','hosts','@up'])
	elapsed = getorraise(document, ['nmaprun','runstats','finished','@elapsed'])
	return "# Nmap done at {} -- {} IP addresses ({} hosts up) scanned in {} seconds".format(timestr, total, up, elapsed)

def getgnmaphost(document):
	ip = getorraise(document, ['address','@addr'])
	hostname = ''
	try:
		hostname = getorraise(document, ['hostnames', 'name'])
	except:
		pass
	status = getorraise(document, ['status','@state']).capitalize()
	ports = gethostportlist(document)
	portstr = "Ports: " + ', '.join([getgnmapport(port) for port in getorraise(ports, ['port'])])
	# Error here: extraports sometimes returns a list, in general this is an issue with getorraise
	filtered = getorraise(ports, ['extraports'])
	filteredcount = 0
	for extra in filtered:
		try:
			state = getorraise(extra, ['@state'])
			if state == 'filtered':
				filteredcount = int(getorraise(extra, ['@count']))
		except:
			pass
	portstr = portstr + "\tIgnored State: filtered ({})".format(filteredcount)

	return "Host: {} ({})\tStatus: {}\nHost: {} ({})\t{}".format(ip, hostname, status, ip, hostname, portstr)

def getgnmapport(document):
	id = getorraise(document, ['@portid'])
	state = getorraise(document, ['state','@state'])
	protocol = getorraise(document, ['@protocol'])
	name = getorraise(document, ['service','@name'])
	return "{}/{}/{}/{}/{}/{}/{}/".format(id, state, protocol, '', name, '', '')

# NMAP routines
def xmltonmap(document):
	nmapdocument = getnmapheader(document) + "\n"
	for host in gethostlist(document):
		nmapdocument = nmapdocument + getnmaphost(host) + "\n"
	nmapdocument = nmapdocument + getnmapfooter(document)
	return nmapdocument

def getnmapheader(document):
	version =  getorraise(document, ['nmaprun','@version'])
	startstr = getorraise(document, ['nmaprun','@startstr'])
	args =	   getorraise(document, ['nmaprun','@args'])
	return "# Nmap {} scan initiated {} as: {}".format(version, startstr, args)

def getnmapfooter(document):
	timestr = getorraise(document, ['nmaprun','runstats','finished','@timestr'])
	total =   getorraise(document, ['nmaprun','runstats','hosts','@total'])
	up =      getorraise(document, ['nmaprun','runstats','hosts','@up'])
	elapsed = getorraise(document, ['nmaprun','runstats','finished','@elapsed'])
	return "# Nmap done at {} -- {} IP addresses ({} hosts up) scanned in {} seconds".format(timestr, total, up, elapsed)

def getnmaphost(document):
	ip = getorraise(document, ['address','@addr'])
	hostname = ''
	try:
		hostname = getorraise(document, ['hostnames', 'name'])
	except:
		pass

	status = getorraise(document, ['status','@state'])
	srtt = '%.3f'%(int(getorraise(document, ['times','@srtt'])) / 1000000.0)
	ports = gethostportlist(document)
	portdoc = getorraise(ports, ['port'])
	if type(portdoc) != list:
		portdoc = [portdoc]

	portstrs = [getnmapport(port) for port in portdoc]
	filtered = getorraise(ports, ['extraports'])
	filteredcount = 0
	for extra in filtered:
		try:
			state = getorraise(extra, ['@state'])
			if state == 'filtered':
				filteredcount = int(getorraise(extra, ['@count']))
		except:
			pass

	# This is used for whitespace calculations
	col1 = max([len(s[0]) for s in portstrs])
	col1 = max(4, col1)+1
	col2 = max([len(s[1]) for s in portstrs])
	col2 = max(5, col2)+1
	portstr = '\n'.join([(s[0] + " "*(col1-len(s[0])) + s[1] + " "*(col2-len(s[1])) + s[2] + "\n" + s[3]) for s in portstrs])

	return ("Nmap scan report for {}\nHost is {} ({}s latency).\nNot shown: {} filtered ports\nPORT" + (" "*(col1-4)) + "STATE" + (" "*(col2-5)) + "SERVICE\n{}\n").format(ip, status, srtt, filteredcount, portstr)

def getnmapport(document):
	id = getorraise(document, ['@portid'])
	state = getorraise(document, ['state','@state'])
	protocol = getorraise(document, ['@protocol'])
	name = getorraise(document, ['service','@name'])
	script = getorraise(document, ['script'])
	info = ""
	for s in script:
		id = getorraise(s, ['@id'])
		output = getorraise(s, ['@output'])
		ol = output.split("\n")
		ol[0] = "{}: {}".format(id, ol[0])
		if len(ol) == 1:
			info = info + "|_{}".format(ol[0]) + "\n"
		else:
			info = info + "| {}".format(ol[0]) + "\n"
		for o in ol[1:-1]:
			info = info + "| {}".format(o) + "\n"
		if len(ol) > 1:
			info = info + "|_{}".format(ol[-1]) + "\n"
	return ["{}/{}".format(id, protocol), state, name, info]

# Structured data
def gethostlist(document):
	hosts = getorraise(document, ['nmaprun','host'])
	if type(hosts) == list:
		return hosts
	else:
		return [hosts]

def gethostportlist(document):
	ports = getorraise(document, ['ports'])
	if type(ports) == list:
		return ports
	else:
		return ports

# Main
with open(sys.argv[1]) as fd:
	doc = xmltodict.parse(fd.read())
	printtree(0, doc)
#	print(xmltognmap(doc))
	print(xmltonmap(doc))
