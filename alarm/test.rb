require 'packetfu'

#using wlan cause I dont have packets on eth0
stream = PacketFu::Capture.new(:start => true, :iface => 'wlan0', :promisc => true)
inc_num = 0;

stream.start

sleep 3
stream.save


# figure out how to do this for each packet
stream.stream.each do |raw|
packet = PacketFu::Packet.parse(packet = raw)
    protocol = packet.proto();  

 protocol = packet.proto()[-1]
puts 
    if (protocol == "TCP")
   puts 
   puts packet.payload.index(/nmap/i)
  end
end


