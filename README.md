# -Configuring-Site-to-Site-VPNs-
The primary objective is to establish a secure, encrypted tunnel between R1 and R3 to protect traffic flowing  between their respective Local Area Networks (LANs).

# Objective
    
- Verify connectivity throughout the network. 
- Configure R1 to support a site-to-site IPsec VPN with R3.

# Skills Learned

- IPsec Protocol Mastery: Gained hands-on experience in implementing and verifying IPsec (Internet Protocol Security), understanding its role in providing secure transmission and authentication over unsecure networks.
- Tunneling Concepts: Established a secure, encrypted Site-to-Site VPN tunnel between two enterprise LANs (R1 and R3) over an intermediary, non-participating network segment (R2)
- IKE Phase 1 (ISAKMP) Policy: Configured IKE Phase 1 parameters for secure key negotiation and peer authentication, including:
  - Encryption: Using AES 256 algorithm.
  - Hashing: Using SHA-1 algorithm.
  - Authentication: Using Pre-shared keys (vpnpa55).
  - Key Exchange: Using Diffie-Hellman Group 5.
- IKE Phase 2 (IPsec) Policy: Defined the IPsec security association (SA) parameters:
  - Transform-Set: Created and applied a transform-set (VPN-SET) specifying esp-aes (Encryption) and esp-sha-hmac (Authentication).
  - Crypto Map: Created and configured a crypto map (VPN-MAP) to bind all IPsec policies to the external interface and define the remote peer (e.g., 10.2.2.2 or 10.1.1.2)
- Traffic Filtering (ACLs): Configured an Extended Access Control List (ACL 110) to precisely identify and define "interesting traffic" (traffic to be encrypted/decrypted) between the two LANs
- Network Verification: Used verification commands (e.g., ping, show version, show crypto ipsec sa, show crypto isakmp sa) to test basic connectivity, confirm security license enablement, and verify the successful establishment and operation of the VPN tunnel
- Traffic Differentiation: Demonstrated the ability to verify that uninteresting traffic is not encrypted by the VPN tunnel.

# Commands Used

Router R1 Configuration
Step	Command	Context / Description	Source
1. Enable Security License	license boot module c1900 technology-package securityk9	
Enables the required security package for IPsec functionality.

ACCEPT	
Accepts the End-User License Agreement (EULA).

copy running-config startup-config	
Saves the configuration to make the license permanent.

reload	
Reboots the router to activate the security license (implicit in instructions).

2. Identify Interesting Traffic	access-list 110 permit ip 192.168.1.0 0.0.0.255 192.168.3.0 0.0.0.255	
Creates an extended ACL (110) defining traffic from the R1 LAN (192.168.1.0/24) to the R3 LAN (192.168.3.0/24) as "interesting" (to be encrypted).

3. Configure IKE Phase 1 (ISAKMP)	crypto isakmp policy 10	
Starts the creation of ISAKMP policy 10.

encryption aes 256	
Sets the encryption algorithm to AES 256.

authentication pre-share	
Sets the authentication method to pre-shared keys.

group 5	
Sets the Diffie-Hellman (DH) group for key exchange.

exit	
Returns to global configuration mode.

crypto isakmp key vpnpa55 address 10.2.2.2	
Defines the pre-shared key (vpnpa55) for the remote peer (R3's external IP: 10.2.2.2).

4. Configure IKE Phase 2 (IPsec)	crypto ipsec transform-set VPN-SET esp-aes esp-sha-hmac	
Creates the transform-set VPN-SET using ESP with AES for encryption and SHA-HMAC for authentication.

crypto map VPN-MAP 10 ipsec-isakmp	
Creates the crypto map VPN-MAP with sequence 10, specifying IPsec/ISAKMP.

description VPN connection to R3	
Adds a descriptive label to the crypto map.

set peer 10.2.2.2	
Specifies R3's external IP address as the VPN peer.

set transform-set VPN-SET	
Binds the Phase 2 parameters to the crypto map.

match address 110	
Binds the ACL (110) defining interesting traffic to the crypto map.

5. Apply Crypto Map	interface s0/0/0	
Enters the interface configuration for R1's WAN port.

crypto map VPN-MAP	
Applies the configured crypto map to the outgoing interface.


Router R3 Configuration

Based on the document "Configuring Site-to-Site VPNs.pdf," here is the comprehensive list of Cisco IOS commands used to establish and verify the IPsec VPN tunnel between Router R1 and Router R3.

Commands Used Section
Router R1 Configuration
Step	Command	Context / Description	Source
1. Enable Security License	license boot module c1900 technology-package securityk9	
Enables the required security package for IPsec functionality.

ACCEPT	
Accepts the End-User License Agreement (EULA).

copy running-config startup-config	
Saves the configuration to make the license permanent.

reload	
Reboots the router to activate the security license (implicit in instructions).

2. Identify Interesting Traffic	access-list 110 permit ip 192.168.1.0 0.0.0.255 192.168.3.0 0.0.0.255	
Creates an extended ACL (110) defining traffic from the R1 LAN (192.168.1.0/24) to the R3 LAN (192.168.3.0/24) as "interesting" (to be encrypted).

3. Configure IKE Phase 1 (ISAKMP)	crypto isakmp policy 10	
Starts the creation of ISAKMP policy 10.

encryption aes 256	
Sets the encryption algorithm to AES 256.

authentication pre-share	
Sets the authentication method to pre-shared keys.

group 5	
Sets the Diffie-Hellman (DH) group for key exchange.

exit	
Returns to global configuration mode.

crypto isakmp key vpnpa55 address 10.2.2.2	
Defines the pre-shared key (vpnpa55) for the remote peer (R3's external IP: 10.2.2.2).

4. Configure IKE Phase 2 (IPsec)	crypto ipsec transform-set VPN-SET esp-aes esp-sha-hmac	
Creates the transform-set VPN-SET using ESP with AES for encryption and SHA-HMAC for authentication.

crypto map VPN-MAP 10 ipsec-isakmp	
Creates the crypto map VPN-MAP with sequence 10, specifying IPsec/ISAKMP.

description VPN connection to R3	
Adds a descriptive label to the crypto map.

set peer 10.2.2.2	
Specifies R3's external IP address as the VPN peer.

set transform-set VPN-SET	
Binds the Phase 2 parameters to the crypto map.

match address 110	
Binds the ACL (110) defining interesting traffic to the crypto map.

5. Apply Crypto Map	interface s0/0/0	
Enters the interface configuration for R1's WAN port.

crypto map VPN-MAP	
Applies the configured crypto map to the outgoing interface.


Router R3 Configuration
Step	Command	Context / Description	Source
1. Identify Interesting Traffic	access-list 110 permit ip 192.168.3.0 0.0.0.255 192.168.1.0 0.0.0.255	
Creates a reciprocal extended ACL (110) defining traffic from the R3 LAN (192.168.3.0/24) to the R1 LAN (192.168.1.0/24) as interesting.

2. Configure IKE Phase 1 (ISAKMP)	crypto isakmp policy 10	
Starts the creation of ISAKMP policy 10.

encryption aes 256	
Sets the encryption algorithm to AES 256.

authentication pre-share	
Sets the authentication method to pre-shared keys.

group 5	
Sets the Diffie-Hellman (DH) group for key exchange.

exit	
Returns to global configuration mode.

crypto isakmp key vpnpa55 address 10.1.1.2	
Defines the pre-shared key (vpnpa55) for the remote peer (R1's external IP: 10.1.1.2).

3. Configure IKE Phase 2 (IPsec)	crypto ipsec transform-set VPN-SET esp-aes esp-sha-hmac	
Creates the transform-set VPN-SET (same as R1).

crypto map VPN-MAP 10 ipsec-isakmp	
Creates the crypto map VPN-MAP with sequence 10, specifying IPsec/ISAKMP.

description VPN connection to R1	
Adds a descriptive label to the crypto map.

set peer 10.1.1.2	
Specifies R1's external IP address as the VPN peer.

set transform-set VPN-SET	
Binds the Phase 2 parameters to the crypto map.

match address 110	Binds the ACL (110) defining interesting traffic to the crypto map (implied, following the setup pattern).	
4. Apply Crypto Map	interface s0/0/1	
Enters the interface configuration for R3's WAN port (based on the Addressing Table).

crypto map VPN-MAP	Applies the configured crypto map to the outgoing interface (implied, following the setup pattern).

Based on the document "Configuring Site-to-Site VPNs.pdf," here is the comprehensive list of Cisco IOS commands used to establish and verify the IPsec VPN tunnel between Router R1 and Router R3.

Commands Used Section
Router R1 Configuration
Step	Command	Context / Description	Source
1. Enable Security License	license boot module c1900 technology-package securityk9	
Enables the required security package for IPsec functionality.

ACCEPT	
Accepts the End-User License Agreement (EULA).

copy running-config startup-config	
Saves the configuration to make the license permanent.

reload	
Reboots the router to activate the security license (implicit in instructions).

2. Identify Interesting Traffic	access-list 110 permit ip 192.168.1.0 0.0.0.255 192.168.3.0 0.0.0.255	
Creates an extended ACL (110) defining traffic from the R1 LAN (192.168.1.0/24) to the R3 LAN (192.168.3.0/24) as "interesting" (to be encrypted).

3. Configure IKE Phase 1 (ISAKMP)	crypto isakmp policy 10	
Starts the creation of ISAKMP policy 10.

encryption aes 256	
Sets the encryption algorithm to AES 256.

authentication pre-share	
Sets the authentication method to pre-shared keys.

group 5	
Sets the Diffie-Hellman (DH) group for key exchange.

exit	
Returns to global configuration mode.

crypto isakmp key vpnpa55 address 10.2.2.2	
Defines the pre-shared key (vpnpa55) for the remote peer (R3's external IP: 10.2.2.2).

4. Configure IKE Phase 2 (IPsec)	crypto ipsec transform-set VPN-SET esp-aes esp-sha-hmac	
Creates the transform-set VPN-SET using ESP with AES for encryption and SHA-HMAC for authentication.

crypto map VPN-MAP 10 ipsec-isakmp	
Creates the crypto map VPN-MAP with sequence 10, specifying IPsec/ISAKMP.

description VPN connection to R3	
Adds a descriptive label to the crypto map.

set peer 10.2.2.2	
Specifies R3's external IP address as the VPN peer.

set transform-set VPN-SET	
Binds the Phase 2 parameters to the crypto map.

match address 110	
Binds the ACL (110) defining interesting traffic to the crypto map.

5. Apply Crypto Map	interface s0/0/0	
Enters the interface configuration for R1's WAN port.

crypto map VPN-MAP	
Applies the configured crypto map to the outgoing interface.


Router R3 Configuration
Step	Command	Context / Description	Source
1. Identify Interesting Traffic	access-list 110 permit ip 192.168.3.0 0.0.0.255 192.168.1.0 0.0.0.255	
Creates a reciprocal extended ACL (110) defining traffic from the R3 LAN (192.168.3.0/24) to the R1 LAN (192.168.1.0/24) as interesting.

2. Configure IKE Phase 1 (ISAKMP)	crypto isakmp policy 10	
Starts the creation of ISAKMP policy 10.

encryption aes 256	
Sets the encryption algorithm to AES 256.

authentication pre-share	
Sets the authentication method to pre-shared keys.

group 5	
Sets the Diffie-Hellman (DH) group for key exchange.

exit	
Returns to global configuration mode.

crypto isakmp key vpnpa55 address 10.1.1.2	
Defines the pre-shared key (vpnpa55) for the remote peer (R1's external IP: 10.1.1.2).

3. Configure IKE Phase 2 (IPsec)	crypto ipsec transform-set VPN-SET esp-aes esp-sha-hmac	
Creates the transform-set VPN-SET (same as R1).

crypto map VPN-MAP 10 ipsec-isakmp	
Creates the crypto map VPN-MAP with sequence 10, specifying IPsec/ISAKMP.

description VPN connection to R1	
Adds a descriptive label to the crypto map.

set peer 10.1.1.2	
Specifies R1's external IP address as the VPN peer.

set transform-set VPN-SET	
Binds the Phase 2 parameters to the crypto map.

match address 110	Binds the ACL (110) defining interesting traffic to the crypto map (implied, following the setup pattern).	
4. Apply Crypto Map	interface s0/0/1	
Enters the interface configuration for R3's WAN port (based on the Addressing Table).

crypto map VPN-MAP	Applies the configured crypto map to the outgoing interface (implied, following the setup pattern).	

Verification Commands
Command	Purpose	Source
show version	
Used to verify the Security Technology package license is enabled.

show crypto isakmp sa	
Verifies that the IKE Phase 1 (ISAKMP) security association is established (in QM_IDLE state).

show crypto ipsec sa	
Verifies that the IKE Phase 2 (IPsec) security association is established and confirms packets are being encrypted/decrypted.

ping [PC-C IP]	
Used to initiate interesting traffic and test end-to-end connectivity.

# Steps
Part 1: Configure IPsec Parameters on R1 
Step 1: Test connectivity. 
Ping from PC-A to PC-C.

<img width="1366" height="503" alt="Screenshot (639)" src="https://github.com/user-attachments/assets/96955f52-70eb-4194-8650-e9b3d6fb5482" />

Step 2: Enable the Security Technology package. 
a.Enable the security technology package by using the following command to enable the package. 
R1(config)# license boot module c1900 technology-package securityk9

<img width="1366" height="490" alt="Screenshot (640)" src="https://github.com/user-attachments/assets/03145c91-af91-4e3d-8b7b-c708459a8e81" />

b.Accept the end-user license agreement. 

<img width="1366" height="489" alt="Screenshot (641)" src="https://github.com/user-attachments/assets/74ae2e3f-9f9c-49d0-b3b3-973d35615676" />

c.Save the running-config and reload the router to enable the security license. 

<img width="1221" height="505" alt="Screenshot (642)" src="https://github.com/user-attachments/assets/a7b5fd45-6017-4846-b1cc-6a4f68f7f6b7" />

<img width="1162" height="512" alt="Screenshot (643)" src="https://github.com/user-attachments/assets/6f2257da-15ad-4471-a689-3165a7649236" />

d.Verify that the Security Technology package has been enabled by using the show version command.

<img width="1148" height="498" alt="Screenshot (644)" src="https://github.com/user-attachments/assets/f9876790-e731-4683-8ded-0906a8b4f5b8" />

Step 3: Identify interesting traffic on R1. 
Configure ACL 110 to identify the traffic from the LAN on R1 to the LAN on R3 as interesting. This interesting traffic will trigger the IPsec VPN to be implemented when there is traffic between the R1 to R3 LANs. All other traffic sourced from the LANs will not be encrypted. Because of the implicit deny all, there is no need to configure a deny ip any any statement. 

<img width="1197" height="484" alt="Screenshot (645)" src="https://github.com/user-attachments/assets/9a0ba307-465f-4b6f-a276-ff7249817819" />

Step 4: Configure the IKE Phase 1 ISAKMP policy on R1. 
Configure the crypto ISAKMP policy 10 properties on R1 along with the shared crypto key vpnpa55. 
Refer to the ISAKMP Phase 1 table for the specific parameters to configure. Default values do not have 
to be configured. Therefore, only the encryption method, key exchange method, and DH method must 
be configured. 
Note: The highest DH group currently supported by Packet Tracer is group 5. In a production network, 
you would configure at least DH 14. 
R1(config)# crypto isakmp policy 10 
R1(config-isakmp)# encryption aes 256 
R1(config-isakmp)# authentication pre-share 
R1(config-isakmp)# group 5 
R1(config-isakmp)# exit 
R1(config)# crypto isakmp key vpnpa55 address 10.2.2.2

<img width="1122" height="512" alt="Screenshot (646)" src="https://github.com/user-attachments/assets/f2b666ab-a9f7-498f-8cc4-20a23da5d4d3" />

Step 5: Configure the IKE Phase 2 IPsec policy on R1. 
a.Create the transform-set VPN-SET to use esp-aes and esp-sha-hmac. 
R1(config)# crypto ipsec transform-set VPN-SET esp-aes esp-sha-hmac

<img width="1003" height="480" alt="Screenshot (647)" src="https://github.com/user-attachments/assets/2a6620f4-0987-4a3e-b0d2-221cdeee191e" />

b.Create the crypto map VPN-MAP that binds all of the Phase 2 parameters together. Use sequence 
number 10 and identify it as an ipsec-isakmp map. 
R1(config)# crypto map VPN-MAP 10 ipsec-isakmp 
R1(config-crypto-map)# description VPN connection to R3 
R1(config-crypto-map)# set peer 10.2.2.2 
R1(config-crypto-map)# set transform-set VPN-SET 
R1(config-crypto-map)# match address 110 
R1(config-crypto-map)# exit 

<img width="1168" height="485" alt="Screenshot (648)" src="https://github.com/user-attachments/assets/94ce261c-2c53-4089-a78f-4e2cdebf1ab6" />

Step 6: Configure the crypto map on the outgoing interface. 
Bind the VPN-MAP crypto map to the outgoing Serial 0/0/0 interface. 
R1(config)# interface s0/0/0 
R1(config-if)# crypto map VPN-MAP 

<img width="1104" height="530" alt="Screenshot (649)" src="https://github.com/user-attachments/assets/a470a251-47a5-48d6-8d5d-d9ba1c30f228" />

Part 2: Configure IPsec Parameters on R3 
Step 1: Enable the Security Technology package. 
a.On R3, issue the show version command to verify that the Security Technology package license 
information has been enabled. 
b.If the security technology package has not been enabled, enable the package and reload R3.

<img width="1144" height="498" alt="Screenshot (650)" src="https://github.com/user-attachments/assets/946ffa63-a580-4167-bf1c-504068b44060" />

Step 2: Configure router R3 to support a site-to-site VPN with R1. 
Configure reciprocating parameters on R3. Configure ACL 110 to identify the traffic from the LAN on 
R3 to the LAN on R1 as interesting. 
R3(config)# access-list 110 permit ip 192.168.3.0 0.0.0.255 192.168.1.0 0.0.0.255

<img width="1167" height="499" alt="Screenshot (651)" src="https://github.com/user-attachments/assets/8e3663f1-6758-435f-a0e8-ee995c692e41" />

Step 3: Configure the IKE Phase 1 ISAKMP properties on R3. 
Configure the crypto ISAKMP policy 10 properties on R3 along with the shared crypto key vpnpa55. 
R3(config)# crypto isakmp policy 10 
R3(config-isakmp)# encryption aes 256 
R3(config-isakmp)# authentication pre-share 
R3(config-isakmp)# group 5 
R3(config-isakmp)# exit 
R3(config)# crypto isakmp key vpnpa55 address 10.1.1.2

<img width="1122" height="537" alt="Screenshot (652)" src="https://github.com/user-attachments/assets/3e945ab9-07e1-420e-aaf2-f948953a4428" />

Step 4: Configure the IKE Phase 2 IPsec policy on R3. 
c.Create the transform-set VPN-SET to use esp-aes and esp-sha-hmac. 
R3(config)# crypto ipsec transform-set VPN-SET esp-aes esp-sha-hmac 

<img width="1096" height="495" alt="Screenshot (653)" src="https://github.com/user-attachments/assets/f8e22bf4-e686-40dc-b391-3c40ce4c3412" />

d.Create the crypto map VPN-MAP to bind all of the Phase 2 parameters together. Use sequence 
number 10 and identify it as an ipsec-isakmp map. 
R3(config)# crypto map VPN-MAP 10 ipsec-isakmp 
R3(config-crypto-map)# description VPN connection to R1 
R3(config-crypto-map)# set peer 10.1.1.2 
R3(config-crypto-map)# set transform-set VPN-SET 
R3(config-crypto-map)# match address 110 
R3(config-crypto-map)# exit 

<img width="1178" height="491" alt="Screenshot (654)" src="https://github.com/user-attachments/assets/4b552140-dde3-47f1-8986-53f9129a745c" />

Step 5: Configure the crypto map on the outgoing interface. 
Bind the VPN-MAP crypto map to the outgoing Serial 0/0/1 interface. 
R3(config)# interface s0/0/1 
R3(config-if)# crypto map VPN-MAP

<img width="1141" height="505" alt="Screenshot (655)" src="https://github.com/user-attachments/assets/8f7357e7-ce67-4e7a-90ce-2c957c50b459" />

Part 3: Verify the IPsec VPN 
Step 1: Verify the tunnel prior to interesting traffic. 
Issue the show crypto ipsec sa command on R1. Notice that the number of packets encapsulated, 
encrypted, decapsulated, and decrypted are all set to 0.

<img width="1214" height="507" alt="Screenshot (656)" src="https://github.com/user-attachments/assets/1970f19e-6b04-4549-811d-37d075836c55" />

Step 2: Create interesting traffic. 
Ping PC-C from PC-A.

<img width="1181" height="497" alt="Screenshot (657)" src="https://github.com/user-attachments/assets/e06c2bf3-9784-45d6-9508-ce81992a5b90" />

Step 3: Verify the tunnel after interesting traffic. 
On R1, re-issue the show crypto ipsec sa command. Notice that the number of packets is more than 0, 
which indicates that the IPsec VPN tunnel is working. 

<img width="1080" height="512" alt="Screenshot (658)" src="https://github.com/user-attachments/assets/387d9631-abd1-4fd2-b99d-e49a95055ca9" />

Step 4: Create uninteresting traffic. 
Ping PC-B from PC-A. Note: Issuing a ping from router R1 to PC-C or R3 to PC-A is not interesting 
traffic.

<img width="1130" height="506" alt="Screenshot (659)" src="https://github.com/user-attachments/assets/8796f3f7-9682-4070-b132-cdffc6635fe1" />

Step 5: Verify the tunnel. 
On R1, re-issue the show crypto ipsec sa command. Notice that the number of packets has not changed, 
which verifies that uninteresting traffic is not encrypted. 

<img width="1125" height="504" alt="Screenshot (660)" src="https://github.com/user-attachments/assets/5a3257ae-e31f-40e3-a6c5-89be390a90de" />

Step 6: Check results. 
Your completion percentage should be 100%. Click Check Results to see feedback and verification of 
which required components have been completed. 

<img width="1233" height="508" alt="Screenshot (661)" src="https://github.com/user-attachments/assets/6600fe40-b8a5-42d3-a1f8-b3bb16de8b25" />

# Conclusion

In conclusion, successfully configuring the site-to-site IPsec VPN between R1 and R3 achieves the goal 
of securing sensitive LAN traffic as it traverses the public or untrusted network segment via the 
intermediary, unaware router R2. By implementing the full IPsec protocol suite—including IKE/ISAKMP 
for Phase 1 key exchange and IPsec transforms (AH/ESP) for Phase 2 data protection—a robust, 
encrypted, and authenticated tunnel is established. This final configuration ensures confidentiality and 
integrity for all data transmitted between the two corporate sites, demonstrating the critical role of network
layer security in building secure wide area networks.























