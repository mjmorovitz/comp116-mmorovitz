require 'packetfu'

stream = PacketFu::Capture.new(:start => true, :iface => 'wlan0', :promisc => true)
stream.show_live()
		
