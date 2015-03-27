# udp_tunnel
- It's used to fuck the GFW.
- Features:
 - Port number randomization. Heavy load on a single port would normally trigger the GFW very soon, so let's open 1000 ports instead.
 - AES encription.
 - Using a tun device, just like openvpn.
 - Dynamic anti packet loss. 10% packet loss? Let's send each packet twice, so we get 1% packet loss rate by sacrificing half of the bandwidth. (TBD)
 - Anti protocol detection, no plan text negotiation and every packet is encrypted.

- Don't ask me any question, I won't answer you!
- Patches are welcome.
