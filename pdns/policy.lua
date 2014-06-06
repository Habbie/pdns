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

function getslot (ts)
	idx = (ts % conf.window) + 1
	if window[idx]
	then
		if window[idx][1] == ts
		then
			return window[idx][2]
		end
	end

	newslot = {0, 0, 0}
	window[idx] = {ts, newslot}
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

function police (req, resp)
	mywindow = getwindow()
	now = os.time()
	print ("= ", os.time())

	if req
	then
		-- print ("> ", req, req:getQuestion(), req:getRemote(), req:getSize())
		mywindow[1][1] = mywindow[1][1]+1
	end
	if resp
	then
		-- print ("< ", resp, resp:getQuestion(), req:getRemote(), resp:getSize() )
		mywindow[1][1] = mywindow[1][1]+1
		mywindow[1][2] = mywindow[1][2]+req:getSize()
		mywindow[1][3] = mywindow[1][3]+resp:getSize()
	end
	print("qps stats last", conf.window, "seconds: ")
	for i = 1, conf.window
	do
		print(mywindow[i][1], mywindow[i][2], mywindow[i][3])
	end
		
	print("--")
end
