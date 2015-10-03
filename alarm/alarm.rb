require 'packetfu'

def write_alert(incident_number, attack, source_ip, protocol, payload)
	puts "#{incident_number}. ALERT: #{attack} is detected from #{source_ip} (#{protocol})!"
end


while true 
    puts "Options"
    puts "1 : Analyze network packets"
    puts "2 : Analyze web server log"
    input = gets.chomp
    
    if (input == "1")
            valid_input = false
            
            while valid_input == false do
                puts "Options"
                puts "1 : Analyze live stream of network packets"
                puts "2 : Analyze PCAP file"
                input = gets.chomp
                if (input == "1")
                    valid_input = true;
                    #using wlan cause I dont have packets on eth0
                    stream = PacketFu::Capture.new(:start => true, :iface => 'wlan0', :promisc => true)
                    data = stream.stream
                elsif (input == "2")
                    valid_input = true
                    puts "Enter file destination"
                    file = gets.chomp
                    packet_arr = PacketFu::PcapFile.read(file)
                    data = packet_arr
                else
                    puts "Invalid option"
                end
            end
         
        inc_num = 0;    
        data.each do |raw| 
            packet = PacketFu::Packet.parse(raw);
            protocol = packet.proto()[-1]; 
            payload = packet.payload;
           if (protocol == "TCP")
            flags = packet.tcp_flags
            src = packet.ip_saddr()
                # NULL scan check
                if (flags.urg == 0) && (flags.ack == 0) && (flags.psh == 0) && (flags.rst ==0) && (flags.syn == 0) && (flags.fin == 0)
	                inc_num += 1;
	                write_alert(inc_num, "NULL scan", src, protocol, payload);
                end
                # FIN scan check
                if (flags.urg == 0) && (flags.ack == 0) && (flags.psh == 0) && (flags.rst ==0) && (flags.syn == 0) && (flags.fin == 1)
	                inc_num += 1;
	                write_alert(inc_num, "FIN scan", src, protocol, payload);
                end
                #Xmas scan check
                if (flags.urg == 1) && (flags.psh == 1) && (flags.fin == 1)
	                inc_num += 1;
	                write_alert(inc_num, "Xmas scan", src , protocol, payload);
	            end
                if ( packet.payload.index(/nmap/i) != nil)
                    inc_num += 1; 
                end
                if ( packet.payload.index(/nikto/i) != nil)
                    inc_num += 1; 
                    write_alert(inc_num, "Nikto scan", src , protocol, payload);
                end
                if (packet.payload.index(/\b(?:4[0-9]{12}(?:[0-9]{3})?|5[12345][0-9]{14}|3[47][0-9]{13}|3(?:0[012345]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35[0-9]{3})[0-9]{11})\b/) != nil)
                    inc_num += 1;
                    write_alert(inc_num, "Credit Card numbers in plain text", src, protocol, payload);
                end
            end
            
     end
     if inc_num == 0
        puts "No scans or other malicious acts detected"
     end
     elsif (input == "2")
        inc_num = 0;
        f = File.open("access.log", "r")
        f.each_line do |line|
            if (line.index(/phpmyadmin/i) != nil)
                inc_num += 1;
                write_alert(inc_num, "phpMyAdmin detected", "", "", line)
            end
             if (line.index(/masscan/i) != nil)
                inc_num += 1;
                write_alert(inc_num, "Masscan detected", "", "", line)
            end
              if (line.index(/nikto/i) != nil)
                inc_num += 1;
                write_alert(inc_num, "Nikto scan detected", "", "", line)
             end
              if (line.index(/nmap/i) != nil)
                inc_num += 1;
                write_alert(inc_num, "NMAP detected", "", "", line)
             end
               if (line.index(/{ :;}/) != nil)
                inc_num += 1;
                write_alert(inc_num, "Shellshock vulnerability scan detected", "", "", line)
             end
             
              if (line.index(/\\[xX][0-9a-fA-F]+/) != nil)
                inc_num += 1;
                write_alert(inc_num, "Shellcode detected", "", "", line)
             end
             
        end
    f.close
    if inc_num == 0
        puts "No scans or other malicious acts detected"
    end
     
     else
     puts "invalid option"
     end
 end
 
 
 
