require 'packetfu'

def write_alert(incident_number, attack, source_ip, protocol)
	puts "#{incident_number}. ALERT: #{attack} is detected from #{source_ip} (#{protocol})!(#{payload})!"
end


while true 
    puts "Options"
    puts "1 : Analyze live stream of network packets"
    puts "2 : Analyze web server log"
    input = gets.chomp
    
    if (input == "1")
        #using wlan cause I dont have packets on eth0
        stream = PacketFu::Capture.new(:start => true, :iface => 'wlan0', :promisc => true)
        inc_num = 0;

        stream.stream.each do |raw| 
            packet = PacketFu::Packet.parse(raw);
            protocol = packet.proto()[-1]; 
            
           if (protocol == "TCP")
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
                if ( packet.payload.index(/nmap/i) != nil)
                    inc_num += 1; 
                end
                if ( packet.payload.index(/nikto/i) != nil)
                    inc_num += 1; 
                    write_alert(inc_num, "Nikto scan", src , protocol);
                end
                if (packet.payload.index(/\b(?:4[0-9]{12}(?:[0-9]{3})?|5[12345][0-9]{14}|3[47][0-9]{13}|3(?:0[012345]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35[0-9]{3})[0-9]{11})\b/) != nil)
                    inc_num += 1;
                    write_alert(inc_num, "Credit Card numbers in plain text", src, protocol);
                end
            end
     end
     elsif (input == "2")
        f = File.open("access.log", "r")
        f.each_line do |line|
            if (line.index(/phpmyadmin/i) != nil)
                inc_num += 1;
                write_alert(inc_num, "phpMyAdmin detected", "", "")
            end
             if (line.index(/masscan/i) != nil)
                inc_num += 1;
                write_alert(inc_num, "Masscan detected", "", "")
            end
              if (line.index(/nikto/i) != nil)
                inc_num += 1;
                write_alert(inc_num, "Nikto scan detected", "", "")
             end
              if (line.index(/nmap/i) != nil)
                inc_num += 1;
                write_alert(inc_num, "NMAP detected", "", "")
             end
        end
f.close


     
     else
     puts "invalid option"
     end
 end
 
 
 
