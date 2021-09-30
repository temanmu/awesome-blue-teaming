# Awesome Blue Teaming

Blue Team :

1. The group responsible for defending an enterprise’s use of information systems by maintaining its security posture against a group of mock attackers (i.e., the Red Team).
2. A group of individuals that conduct operational network vulnerability evaluations and provide mitigation techniques to customers who have a need for an independent technical review of their network security posture. 

https://csrc.nist.gov/glossary/term/blue_team


## List of Blue Team Resources

* [Threat Intelligence](#threat-intelligence)
* [Digital Forensics](#digital-forensics)
* [Incident Response](#incident-response)
* [Security Information and Event Management (SIEM)](#security-information-and-event-management-siem)
* [Phising](#phising)

----------------------------------------------------------------------------------------------------------------------------
#### Threat Intelligence
  * ##### Books
    * [The Threat Intelligence Handbook: A Practical Guide for Security Teams to Unlocking the Power of Intelligence](https://www.amazon.com/Threat-Intelligence-Handbook-Practical-Unlocking/dp/099903546)
    * [Intelligence-Driven Incident Response: Outwitting the Adversary](https://www.amazon.com/Intelligence-Driven-Incident-Response-Outwitting-Adversary/dp/1491934948)
    * [Structured Analytic Techniques for Intelligence Analysis](https://www.amazon.com/Structured-Analytic-Techniques-Intelligence-Analysis/dp/1452241511)
    * [The Cuckoo's Egg: Tracking a Spy Through the Maze of Computer Espionage ](https://www.amazon.com/Cuckoos-Egg-Tracking-Computer-Espionage/dp/0385249462)

  * ##### Courses / Certification
    * [Cyber Threat Intelligence](https://www.coursera.org/learn/ibm-cyber-threat-intelligence)
    * [Certified Threat Intelligence Analyst (C|TIA)](https://www.eccouncil.org/programs/threat-intelligence-training)
    * [Certified Cyber Threat Intelligence Analyst](https://www.udemy.com/course/cybersecurity-threat-intelligence-researcher)
    * [FOR578: Cyber Threat Intelligence](https://www.sans.org/cyber-security-courses/cyber-threat-intelligence)

  * ##### Tools
    <table>
     <tr>
        <td>
            <a href="https://github.com/BinaryDefense/goatrider" target="_blank">GoatRider</a>
        </td>
        <td>
         Tool for doing a comparison of IP addresses or hostnames to BDS Artillery Feeds, OTX, Alexa Top 1M, and TOR.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/1aN0rmus/TekDefense-Automater" target="_blank">TekDefense-Automater</a>
        </td>
        <td>
        Automater is a URL/Domain, IP Address, and Md5 Hash OSINT tool aimed at making the analysis process easier for intrusion Analysts. 
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/opensourcesec/Forager" target="_blank">Forager</a>
        </td>
        <td>
        Multithreaded threat intelligence hunter-gatherer script.
        </td>
     </tr>
     <tr>
        <td>
            <a href="https://github.com/Yelp/threat_intel" target="_blank">threat_intel</a>
        </td>
        <td>
        Threat Intelligence APIs. 
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/InQuest/ThreatIngestor" target="_blank">ThreatIngestor</a>
        </td>
        <td>
        An extendable tool to extract and aggregate IOCs from threat feeds. 
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/activecm/rita" target="_blank">RITA (Real Intelligence Threat Analytics)</a>
        </td>
        <td>
        An open source framework for network traffic analysis.
        </td>
    </tr>
    </table>

  * ##### Other resources
    * [Threat Intelligence CTF Walk-Through: 8Es_Rock OSINT Challenges](https://www.secureworks.com/blog/threat-intelligence-capture-the-flag-walk-through-8esrock)
    * [CTF Academy - Open Source Intelligence](https://ctfacademy.github.io/osint/index.htm)

----------------------------------------------------------------------------------------------------------------------------
#### Digital Forensics
  * ##### Books
    * [Learn Computer Forensics: A beginner's guide to searching, analyzing, and securing digital evidence](https://www.amazon.com/Learn-Computer-Forensics-beginners-searching-ebook/dp/B086WBP289)
    * [The Art of Memory Forensics: Detecting Malware and Threats in Windows, Linux, and Mac Memory](https://www.amazon.com/Art-Memory-Forensics-Detecting-Malware-ebook-dp-B00JUUZSQC/dp/B00JUUZSQC)
    * [Practical Forensic Imaging](https://nostarch.com/forensicimaging)
    * [Handbook of Digital Forensics and Investigation](https://www.amazon.com/Handbook-Digital-Forensics-Investigation-Eoghan-ebook-dp-B00486UK2K/dp/B00486UK2K)

  * ##### Courses / Certification
    * [Digital Forensics and Electronic Evidence](https://www.udemy.com/course/digital-forensics-and-electronic-evidence)
    * [FOR500: Windows Forensic Analysis](https://www.sans.org/cyber-security-courses/windows-forensic-analysis)
    * [eLearnSecurity Certified Digital Forensics Professional](https://elearnsecurity.com/product/ecdfp-certification)
    * [Computer Hacking and Forensics](https://www.cybrary.it/course/computer-hacking-forensics-analyst)

  * ##### Tools
    <table>
     <tr>
        <td>
            <a href="https://github.com/USArmyResearchLab/Dshell" target="_blank">Dshell</a>
        </td>
        <td>
         An extensible network forensic analysis framework. Enables rapid development of plugins to support the dissection of network packet captures.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/volatilityfoundation/volatility" target="_blank">Volatility</a>
        </td>
        <td>
         Volatile memory extraction utility framework
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/keikoproj/kube-forensics" target="_blank">kube-forensics</a>
        </td>
        <td>
         Kube-forensics allows a cluster administrator to dump the current state of a running pod and all its containers so that security professionals can perform off-line forensic analysis.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/jipegit/OSXAuditor" target="_blank">OS X Auditor</a>
        </td>
        <td>
         OS X Auditor is a free Mac OS X computer forensics tool.
        </td>
    </tr>
    </table>

  * ##### Other resources
    * [CTF101 Forensics](https://ctf101.org/forensics/overview)
    * [CTF forensic methods big summary, the proposed collection](https://titanwolf.org/Network/Articles/Article?AID=6f90269f-46df-4e46-adb6-96ded44ad154)
    * [FORENSIC CHALLENGES](https://www.amanhardikar.com/mindmaps/ForensicChallenges.html)

----------------------------------------------------------------------------------------------------------------------------
#### Incident Response
  * ##### Books
    * [Applied Incident Response ](https://www.amazon.com/Applied-Incident-Response-Steve-Anson/dp/1119560268/)
    * [Intelligence-Driven Incident Response: Outwitting the Adversary](https://www.amazon.com/Intelligence-Driven-Incident-Response-Outwitting-Adversary-ebook-dp-B074ZRN5T7/dp/B074ZRN5T7)
    * [Incident Response & Computer Forensics, Third Edition](https://www.amazon.com/Incident-Response-Computer-Forensics-Third/dp/0071798684/)
    * [Operator Handbook: Red Team + OSINT + Blue Team Reference](https://www.amazon.com/Operator-Handbook-Team-OSINT-Reference/dp/B085RR67H5/)

  * ##### Courses / Certification
    * [Cyber Incident Response](https://www.coursera.org/learn/incident-response)
    * [Cyber Security Incident Response](https://www.udemy.com/course/ksc_learn-incident-response/)
    * [eLearnSecurity Certified Incident Responder](https://elearnsecurity.com/product/ecir-certification/)
    * [GIAC Certified Incident Handler (GCIH)](https://www.giac.org/certification/certified-incident-handler-gcih)

  * ##### Tools
    <table>
    <tr>
        <td>
            <a href="https://github.com/ahmedkhlief/APT-Hunter" target="_blank">APT-Hunter</a>
        </td>
        <td>
         APT-Hunter is Threat Hunting tool for windows event logs which made by purple team mindset to provide detect APT movements hidden in the sea of windows event logs to decrease the time to uncover suspicious activity.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/JPCERTCC/SysmonSearch" target="_blank">SysmonSearch</a>
        </td>
        <td>
         SysmonSearch make event log analysis more effective and less time consuming, by aggregating event logs generated by Microsoft's Sysmon.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/JPCERTCC/LogonTracer" target="_blank">Logon Tracer</a>
        </td>
        <td>
         LogonTracer is a tool to investigate malicious logon by visualizing and analyzing Windows Active Directory event logs.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/ThreatResponse/aws_ir" target="_blank">AWS IR</a>
        </td>
        <td>
         Python installable command line utility for mitigation of instance and key compromises.
        </td>
    </tr>
    </table>

  * ##### Other resources
    * [Free DFIR, OSINT & Blue Team CTFs and Challenges](https://freetraining.dfirdiva.com/dfir-ctfs-challenges)

----------------------------------------------------------------------------------------------------------------------------
#### Security Information and Event Management (SIEM)
  * ##### Books
    * [Blue Team Handbook: SOC, SIEM, and Threat Hunting (V1.02): A Condensed Guide for the Security Operations Team and Threat Hunter](https://www.amazon.com/Blue-Team-Handbook-Condensed-Operations/dp/1091493898/)
    * [The Practice of Network Security Monitoring: Understanding Incident Detection and Response](https://www.amazon.com/Practice-Network-Security-Monitoring-Understanding/dp/1593275099)
    * [Crafting the InfoSec Playbook: Security Monitoring and Incident Response Master Plan](https://www.amazon.com/Crafting-InfoSec-Playbook-Security-Monitoring/dp/1491949406/)
    * [Security Information and Event Management (SIEM) Implementation (Network Pro Library)](https://www.amazon.com/Security-Information-Management-Implementation-Network/dp/0071701095/)

  * ##### Courses / Certification
    * [Real-Time Cyber Threat Detection and Mitigation](https://www.coursera.org/learn/real-time-cyber-threat-detection)
    * [Splunk 7.x Fundamentals Part 1 (eLearning)](https://education.splunk.com/course/splunk-7x-fundamentals-part-1-elearning)
    * [BLUE TEAM LEVEL 1 SECURITY OPS CERTIFICATION](https://securityblue.team/why-btl1/)
    * [Splunk Enterprise Security Certified Admin](https://www.splunk.com/en_us/training/certification-track/splunk-es-certified-admin.html)

  * ##### Tools
    <table>
    <tr>
        <td>
            <a href="https://github.com/ossec/ossec-hids" target="_blank">OSSEC</a>
        </td>
        <td>
         OSSEC is a full platform to monitor and control your systems. It mixes together all the aspects of HIDS (host-based intrusion detection), log monitoring and SIM/SIEM together in a simple, powerful and open source solution.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/wazuh/wazuh" target="_blank">Wazuh</a>
        </td>
        <td>
         Wazuh is a free and open source platform used for threat prevention, detection, and response.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/OISF/suricata" target="_blank">Suricata</a>
        </td>
        <td>
         Suricata is a network IDS, IPS and NSM engine.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/snort3/snort3" target="_blank">Snort++</a>
        </td>
        <td>
         Snort 3 is the next generation Snort IPS (Intrusion Prevention System).
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://www.splunk.com/en_us/cyber-security/siem.html" target="_blank">Splunk SIEM</a>
        </td>
        <td>
         Monitor, detect, investigate and respond to threats with streaming, cloud-based security analytics.
        </td>
    </tr>
    </table>

  * ##### Other resources
    * Chall - [Boss Of The SOC v1](https://cyberdefenders.org/labs/15)
    * Chall - [Boss Of The SOC v2](https://cyberdefenders.org/labs/16)
    * Chall - [Boss Of The SOC v3](https://cyberdefenders.org/labs/8)

----------------------------------------------------------------------------------------------------------------------------
#### Phising
  * ##### Books
    * []()

  * ##### Courses / Certification
    * []()
    * 
    * 
    * 

  * ##### Tools
     <table>
    <tr>
        <td>
            <a href="https://github.com/ThreatResponse/aws_ir" target="_blank">AWS IR</a>
        </td>
        <td>
         Python installable command line utility for mitigation of instance and key compromises.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/ThreatResponse/aws_ir" target="_blank">AWS IR</a>
        </td>
        <td>
         Python installable command line utility for mitigation of instance and key compromises.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/ThreatResponse/aws_ir" target="_blank">AWS IR</a>
        </td>
        <td>
         Python installable command line utility for mitigation of instance and key compromises.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/ThreatResponse/aws_ir" target="_blank">AWS IR</a>
        </td>
        <td>
         Python installable command line utility for mitigation of instance and key compromises.
        </td>
    </tr>
    </table>

  * ##### Other resources
    * 




## Contributing
   Feel free to open a pull request 
