global srIPtoUA: table[addr] of set[string];
event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list)
{
local x: set[string];
local UA:string;
	if(hlist[2]$name=="USER-AGENT")
	{
		UA=hlist[2]$value;
		if(c$id$orig_h in srIPtoUA)
		{
			x=srIPtoUA[c$id$orig_h];
			add x[UA];
			srIPtoUA[c$id$orig_h]=x;
		}else
		{
			add x[UA];
			srIPtoUA[c$id$orig_h]=x;
		}
	}	
}
event zeek_done()
{
local x:addr;
	for(x in srIPtoUA)
	{
		if(|srIPtoUA[x]|>=3)
		{
		print cat(x," is a proxy");
		}
	}
}

