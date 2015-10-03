require 'packetfu'

#using wlan cause I dont have packets on eth0
stream = PacketFu::Capture.new(:start => true, :iface => 'wlan0', :promisc => true)
inc_num = 0;

stream.start

sleep 3
stream.save
puts "I AM PRINTING CORRECTLY";
puts stream.stream;
# figure out how to do this for each packet
stream.stream.each do |raw|
packet = PacketFu::Packet.parse(packet = raw)
    protocol = packet.proto();  
puts "prottotype is" 
length =  packet.proto().length
 protocol = packet.proto();  

    if (protocol[length - 1] == "TCP")
    puts "THINK THIS IS TCP"
puts packet.kind_of? PacketFu::TCPPacket
  end
end


