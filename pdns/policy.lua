conf = {}
conf.rps = 5
conf.eps = 5
conf.logonly = false
conf.window = 5
conf.v4len = 24
conf.v6len = 56
conf.leakrate = 3
conf.tcrate = 2

window = {}
timechanged = false

function getslot (ts)
	idx = (ts % conf.window) + 1
	if window[idx]
	then
		if window[idx][1] == ts
		then
			return window[idx][2]
		end
	end

	newslot = {}
	window[idx] = {ts, newslot}
	timechanged = true
	return newslot
end

function getwindow ()
	mywindow = {}
	now = os.time()
	for i = now, now-conf.window+1, -1
	do
		table.insert(mywindow, getslot(i))
	end

	return mywindow
end

function mask (host)
	-- assumes /24 and ipv4
	f = host:gmatch('%d+')
	return f().."."..f().."."..f()
end

function police (req, resp)
	timechanged = false
	mywindow = getwindow()
	now = os.time()
	print ("= ", os.time())

	if resp
	then
		qname, qtype = resp:getQuestion()
		remote = resp:getRemote()
		wild = resp:getWild()
		zone = resp:getZone()
		reqsize = req:getSize()
		respsize = resp:getSize()
		rcode = resp:getRcode()
		print ("< ", qname, qtype, remote, "wild: "..wild, "zone: "..zone, reqsize.."/"..respsize, rcode )
		-- mywindow[1][1] = mywindow[1][1]+1
		-- mywindow[1][2] = mywindow[1][2]+req:getSize()
		-- mywindow[1][3] = mywindow[1][3]+resp:getSize()
		an, ns, ar = resp:getRRCounts()
		imputedname = qname
		errorstatus = (rcode == pdns.REFUSED or rcode == pdns.FORMERR or rcode == pdns.SERVFAIL or rcode == pdns.NOTIMP)

		if wild:len() > 0
		then
			imputedname = wild
		elseif rcode == pdns.NXDOMAIN or errorstatus
		then
			imputedname = zone
		end
		token = mask(remote).."/"..imputedname.."/"..tostring(errorstatus)
		print ("token: "..token)
		-- token = { mask(resp:getRemote()), }
	end
	-- if timechanged
	-- then
	-- 	print("qps stats last", conf.window, "seconds: ")
	-- 	for i = 1, conf.window
	-- 	do
	-- 		print(mywindow[i][1], mywindow[i][2], mywindow[i][3])
	-- 	end
	-- end
		
	-- print("--")
end
