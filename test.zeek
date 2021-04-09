global ip2ua :table[addr] of set[string] = table();

event http_all_headers  (c: connection, is_orig: bool, hlist: mime_header_list) {
    local source_ip = c$id$orig_h;

    for (_, rec in hlist) {
        if (rec$name == "USER-AGENT") {
            local ua = to_lower(rec$value);
            if (source_ip in ip2ua) {
                add (ip2ua[source_ip])[ua];
            } else {
                ip2ua[source_ip] = set(ua);
            }
        }
    }
}

event zeek_done() {
    for(ip, ua_set in ip2ua) {
        if(|ua_set| >= 3) {
            print(fmt("%s is a proxy", ip));
        }
    }
}
