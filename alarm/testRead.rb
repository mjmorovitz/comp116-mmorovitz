
	
f = File.open("access.log", "r")
f.each_line do |line|
if (line.index("phpMyAdmin") != nil)
  puts line
  end
end
f.close



  
