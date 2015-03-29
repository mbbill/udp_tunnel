# udp_tunnel
- It's used to fuck the GFW.
- Features:
 - Port number randomization. Heavy load on a single port would trigger the GFW quickly, so let's open 1000 ports instead.
 - AES encription.
 - Using a tun device, just like openvpn.
 - Dynamic anti packet loss. 10% packet loss? Let's send each packet twice, so we get 1% packet loss rate by sacrificing half of the bandwidth. (TBD)
 - Anti protocol detection, no plan text negotiation and every packet is encrypted.

# Note
 - It cannot go across NAT for the moment.

# Usage
 - Server:
  - #./udp_tunnel --mode server --host "ip" --passwd "pass"
  - Enable forwarding: #sysctl -w net.ipv4.ip_forward=1 (or modify the /etc/sysctl.conf)
  - Enable MASQUERADE #iptables -t nat -A POSTROUTING -s 10.9.0.0/24 -o "output dev" -j MASQUERADE

 - Client:
  - #./udp_tunnel --mode client --host "server hostname" --passwd "pass"
  - Add route policies
   - #route add -net "server ip"/32 dev xxx(your default dev)
   - #route add -net 128.0.0.0/1 dev ctun
   - #route add -net 0.0.0.0/1 dev ctun


- Don't ask me any question, I won't answer you!
- Patches are welcome.
