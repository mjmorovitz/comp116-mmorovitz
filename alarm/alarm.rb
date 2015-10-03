require 'packetfu'

def write_alert(incident_number, attack, source_ip, protocol)
	puts "#{incident_number}. ALERT: #{attack} is detected from #{source_ip} (#{protocol})!(#{payload})!"
end

#using wlan cause I dont have packets on eth0
stream = PacketFu::Capture.new(:start => true, :iface => 'wlan0', :promisc => true)
inc_num = 0;

stream.stream.each do |raw| 
    packet = PacketFu::Packet.parse(raw);
    protocol = packet.proto();  
    length = protocol.length;
    
   if (protocol[length - 1] == "TCP")
    flags = packet.tcp_flags
    src = packet.ip_saddr()
        # NULL scan check
        if (flags.urg == 0) && (flags.ack == 0) && (flags.psh == 0) && (flags.rst ==0) && (flags.syn == 0) && (flags.fin == 0)
	        inc_num += 1;
	        write_alert(inc_num, "NULL scan", src, protocol);
        end
        # FIN scan check
        if (flags.urg == 0) && (flags.ack == 0) && (flags.psh == 0) && (flags.rst ==0) && (flags.syn == 0) && (flags.fin == 1)
	        inc_num += 1;
	        write_alert(inc_num, "FIN scan", src, protocol);
        end
        #Xmas scan check
        if (flags.urg == 1) && (flags.psh == 1) && (flags.fin == 1)
	        inc_num += 1;
	        write_alert(inc_num, "Xmas scan", src , protocol);
	    end
    end
    if ( packet.payload.index(/[Nn][Mm][Aa][Pp]/))
        inc_num += 1; 
        write_alert(inc_num, "NMAP scan", src , protocol);
        
end
