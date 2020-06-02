# Incident-Response-Plan

Attack Surface
------------------------------------------------------------------------------------------------------
> Data Breach
			Steps
				1. Activate the IRT (Incident Response Team)
					IRT should include:
            i. An executive with decision making authority
            ii. "First Responder" security & IT personnel with access to systems.
            iii. CTO/ CISO/ CIO
				2. Established a "privileged" reporting and communication channel
					(Ideally before the breach) It will maintain the confidentiality of the investigation.
					Legal counsel should receive all incident reports.
				3. Use independent cyber security and forensic experts
				4. Stop addtional data loss
					Use tools to dynamically image affected systems to preserve evidence prior taking affected systems offline by disconnecting them        from the network. 
				5. Secure evidence
					i. Secure and prevent physical access to affected system to maintain the integrity of the evidence.
					ii.  Preserve all security access devices (tokens, badges, key cards, etc.), logs and surveillance tapes.
            Determine:
						  a. Who had contact with affected system?
						  b. What did they do?
						  c. Who was the next to touch the affected system?
				6. Preserve computer logs
					i. Preserve all affected system log files including firewall, VPN, mail, network, webserver, IDS logs.
					ii. These logs are critical to assess the origin of the attack, its duration and the volume of data exfiltrated during the breach
				7. Document the Data Breach
					i. data, time of the breach
					ii. the personnel who discovered the breach
					iii. the kinds of data stolen/ lost.
					iv. All employees who had access to the affected systems.
					v. Document all data/ or devices affected by in the breach
				8. Interview personnel involved.
				9. Change security access devices and passwords.
			Case Study
				Data of over 7 million BHIM users exposed.
					Root Cause - S3 bucket misconfiguration
            PII leaked
              a. Aadhaar Card Details
              b. Residence proof
              c. Bank Records
				Truecaller - Data of 4.75 crore Indians on Dark Web
					  PII leaked:
              i. Username, gender, age
              ii. Facebook acount
              iii. Email ID
              iv. Mobile number
		
 > Cloud
			Challenges 
				1. Traffic filtering and logs
				2. Log retention period
				3. Access Management
				4. Insecure Host Configurations
			Technologies
				AWS
					Monitoring toolsets
						1. IAM Policy
						2. Cloudwatch
						3. VPCFlow Logs
							Feature that enables to capture information about the IP traffic going to and from network interfaces in VPC.
						4. CloudTrail
							 Service that enables governance, compliance, operational auditing, and risk auditing of  AWS account
						5. Gauardduty
					Incident Domains
						1. Service 
							a. AWS Account
							b. IAM Permissions
							c. Billing
						2. Infrastructure
							It includes data or network related activity, e.g. Traffic to your Amazon EC2 instances with VPC 
						3. Application 
							Related to application code or application deployed in the infra.
				Azure
					Monitoring toolsets
						1. Azure AD logs
						2. NSG Flow Logs
						3. Unified Audit
						4. ATP Logs
		
 > Phishing Attack
			Analysis
				1. The From Field: Contains the name of the sender.
				2. X-Authenticated User: Contains the Email Address of the sender.
				3. Mail Server IP Address
				4. Analysis of the E-mail message
					i. Examine the actual content of the E-mail
					ii. Analysis of Domain link
						a. Perform nslookup and get the IP addressess belonging to the hostname
						b. Do reverse lookup and note the PTR record.
							A Pointer record (PTR) resolves an IP address to a fully-qualified domain name.
						c. Identify if its a campaign
						d. Blackholing DNS 
				5. Use MX-Toolbox for Header Analysis
				6. Block emails on the SMTP Server by identifying the common pattern
				7. Check SMTP logs whether the same email send to other users.
				8. Report malware sample to AV vendor
				9. Deploy AV signature to the endpoints
			Case Study
				COVID-19 Related phishing attacks
		
 > Malware
			Steps
				1. Suspect the file and generate the MD5 hash & send it to malwareDB
				2. If its an unknown malware then send for sandbox for analysis
				3. Check for Encryption capabilities then scan for Crypto Malware processes and files
				4. Scan other systems for the same malware type.
				5. Identify the source and block from Firewall and MailRelays
				6. Recover files from Backup
			Analysis
				1. Get HASH and check on virustotal.com
				2. Use PeStudio for Static Analysis
				3. Monitor process 
					i. Process Hacker
						While execution check the strings from the memory of the process
						Also check Handles tab
					ii. Process Monitor
				4. ProcDot - To get a good diagrammatic representation
				5. totalhash.com
				6. urlvoid.com - Website reputation checker
				7. dnSpy - Useful for reverse engineering
				8. Remnux, FLARE - OS specific for Malware Analysis
				9. fakedns - Used for behaviour analysis of malware
				10. Retrohunt - Allows us to scan all the files sent to VirusTotal in the past 12 months with your YARA rules 
					YARA Rules -  a way of identifying malware (or other files) by creating rules that look for certain characteristics
			Case Study
				Implementation on Decoys to identify the attach of Mirai Botnet
				2. Detection of WannCry - Attacking SMB and Eternalblue exploit
				3. Crypto mining Malware 
					1. PyRoMine
					2. Adylkuzz
						 i. Exploiting the MS17-010 SMB like WannaCry but less noisy
						ii. Unique feauture - Prevent system to infect from other malwares which tries to exploit MS17-010
						iii. Uses LUA language 
		
 > DDoS Attack
			Steps
				Proactive Measures
					1. Use Firewall botnet filter and monitor for outgoing traffic
					2. Check for IRC, P2P protocols
					3. Use Network Monitoring utility like - LANGuardian to identify traffic patterns
					4. Disable DNS recursive queries
					5. Review the load and log files of affected systems
					6. Contact ISP to provide details about traffic sources like source IP addresses, Protocols
				Identification
					1. Increase in the volume of traffic
					2. Consistent increase in bandwidth utilization
					3. Alerts from the Botnet Filter
					4. Abnormal increase in DNS lookups failures
				Containment
					1. Allow only whitelisted IPs
					2. Block the IPs identified as sending throttle traffic
					3. Inform ISP to block the suspicious range of IP addresses and multiple connection requests for the same source
				Eradication
					1. Route traffic through a traffic-scrubbing service or product via DNS or routing changes (e.g. sinkhole routing)
					2. Configure egress filters to block the traffic which your systems may send in response to DDoS 
			
   > Network related Attacks
			Event IDs
				4624 –A logon to a system has occurred.
				4625 -A failed logon attempt.
				4768 –The issuance of a Ticket Granting Ticket (TGT) shows that a particular user account was authenticated by the domain controller
				4672 – Special (Admin) Logon
				4776 – NTLM-based Authentication
				1006 - The antimalware engine found malware or other potentially unwanted software.
				5001 - Real-time protection is disabled.
