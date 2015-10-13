#Assignment 2: Incident Alarm
#Author: Walton Lee

require 'packetfu'

def alert(iname, source, protocol, payload)
    message = "#{$count}. ALERT: #{iname} is detected from #{source} (#{protocol}) (#{payload.unpack('m*')})!"
    $count = $count + 1
    puts message
end

def checkCredit(payload)
    return true if payload.match(/4\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/) != nil
    return true if payload.match(/5\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/) != nil
    return true if payload.match(/6011(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/) != nil
    return true if payload.match(/3\d{3}(\s|-)?\d{6}(\s|-)?\d{5}/) != nil
    return false
end

$count = 1
if ARGV.length == 2 and ARGV[0] == "-r" and File.file?(ARGV[1])
    log = ARGV[1]
    File.open(log) do |f|
        f.each_line do |line|
            ip = line.scan(/(?:[0-9]{1,3}\.){3}[0-9]{1,3}/).first
            protocol = "HTTP"
            protocol = "UDP" if !line.include? "HTTP"
            pload = line.scan(/"(.*?)"/).first
            alert("nmap scan",ip,protocol,pload) if line.include? "Nmap"
            alert("Robert Graham's Masscan",ip,protocol,pload) if line.include? "masscan"
            alert("phpMyAdmin related scan",ip,protocol,pload) if line.include? "phpMyAdmin" 
            alert("shellshock bug",ip,protocol,pload) if line.include? "() { :;};"
            alert("Nikto scan",ip,protocol,pload) if line.include? "nikto"
            alert("Shellcode",ip,protocol,pload) if line.include? '\x'
        end
    end

elsif ARGV.length == 0
    packets = PacketFu::Capture.new(:start => true, :iface => 'eth0', :promisc => true, :save => true)
    packets.stream.each do |p|
        pkt = PacketFu::Packet.parse(p)
        if pkt.kind_of?(PacketFu::IPHeaderMixin)
            pload = pkt.payload
            if pkt.kind_of?(PacketFu::TCPPacket)
                flags = pkt.tcp_flags
                alert("NULL scan",pkt.ip_src,"TCP",pload) if !flags.urg and !flags.ack and !flags.psh and !flags.rst and !flags.syn and !flags.fin
                alert("FIN scan",pkt.ip_src,"TCP",pload) if !flags.urg and !flags.ack and !flags.psh and !flags.rst and !flags.syn and flags.fin
                alert("XMAS scan",pkt.ip_src,"TCP",pload) if flags.urg and !flags.ack and flags.psh and !flags.rst and !flags.syn and flags.fin
            end
            alert("nmap scan", pkt.ip_src,pkt.proto[pkt.proto.size - 1],pload) if pload.include? "nmap" or pload.include? '\4e\6d\61\70' or pload.include? "Nmap"
            alert("nikto scan", pkt.ip_src,pkt.proto[pkt.proto.size - 1],pload) if pload.include? "nikto" or pload.include? '6e\69\6b\74\6f'
            alert("Credit Card Leak", pkt.ip_src,pkt.proto[pkt.proto.size - 1],pload) if checkCredit(pload)
        end
    end
else
    puts "USAGE: ruby alarm.rb [-r <log>]"
end
