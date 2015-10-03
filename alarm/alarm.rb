require 'packetfu'

def write_alert(incident_number, attack, source_ip, protocol)
puts "#{incident_number}. ALERT: #{attack} is detected from #{source_ip} (#{protocol})!(#{payload})!"
end

stream = PacketFu::Capture.new(:start => true, :iface => 'wlan0', :promisc => true)

# figure out how to do this for each packet
packet = PacketFu::Packet.parse();


# NULL scan check
if (flags.urg == 0) && (flags.ack == 0) && (flags.psh == 0) && (flags.rst ==0) && (flags.syn == 0) && (flags.fin == 0)
	inc_num += 1;
	write_alert(inc_num, "NULL scan", SOURCEIP, PROTOCOL);

# FIN scan check
if (flags.urg == 0) && (flags.ack == 0) && (flags.psh == 0) && (flags.rst ==0) && (flags.syn == 0) && (flags.fin == 1)
	inc_num += 1;
	write_alert(inc_num, "FIN scan", SOURCEIP, PROTOCOL);
#Xmas scan check
if (flags.urg == 1) && (flags.psh == 1) && (flags.fin == 1)
	inc_num += 1;
	write_alert(inc_num, "Xmas scan", SOURCEIP, PROTOCOL);
#
