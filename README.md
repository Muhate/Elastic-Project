# Elastic Stack Project

### 1. Description

This home lab project focuses on implementing a SIEM (Security Information and Event Management) using Elastic Stack (Elasticsearch, Logstash and Kibana). We will be installing the Elastic Stack on Ubuntu 24.04 server and we'll be monitoring, detecting and investigating brute force attacks using SSH and RDP protocols. We will create some dashboards and integrate the SIEM with osTicket system, which is ticketing system. 
We will use elastic agents enrolled via fleet server on an Ubuntu machine and elastic agents along with Sysmon on an Windows machine. We will learn how to setup and configure the Fleet Server, elastic agents and Sysmon. We are going to also install and configure Mythic server to emulate a C2 server, which will be used to attack some of the servers.


### 2. Objectives

- Set up a Elastic Stack SIEM to collect, aggregate, correlate and analyze security data.
- Set up and configure Fleet Server to centrally manage the elastic agents.
- Install and configure the osTicket and integrate it to Elastic Stack to create tickets when an alert is triggered.


### 3. Tools and Technologies Used

- **VirtualBox**: Used for creating virtual machines for the lab environment.
- **Wazuh**: SIEM tool for log management and security monitoring;
- **Ubuntu Server 24.04 LTS**: Where we will install Suricata and Wazuh agent.
- **Kali Linux**: Used as an attacker system;


### 4. Lab Setup
   - **Network Diagram**:
   
The diagram below illustrates how the components will be interconnected all together, along with their description and IP addresses details.

<p align="center">
<img width="485" alt="Network Diagram" src="https://github.com/user-attachments/assets/cd0feaa9-b8a5-4853-83ce-df84b73e73f8">
</p>


   - **Components**:
     - **Elastic Stack**: Centralized management console.
     - **Fleet Server**: Installed on target systems to capture network activity and collect logs, respectively.
     - **Elastic agents**: Installed on target systems to capture network activity and collect logs, respectively.

### 5. Installation Steps
   - **5.1. Setting up VirtualBox**

For setting up VirtualBox, refer to <a href="https://github.com/Muhate/Setting-Up-VirtualBox">this guide</a>
<br>
<br>
   
   - **5.2: Setting up Kali Linux on VirtualBox**

For setting up Kali Linux on VirtualBox, refer to <a href="https://github.com/Muhate/Install-Windows-on-VirtualBox">this guide</a>
<br>
<br>

   - **5.3: Setting up Ubuntu Server 24.04.LTS on VirtualBox**

For setting up Ubuntu Server on VirtualBox, refer to <a href="https://github.com/Muhate/Install-Ubuntu-on-VirtualBox">this guide</a>
<br>
<br>

   - **5.4: Setting up Elastic Stack on Ubuntu Server 24.04 LTS**

     - After logging into the server, update the package manager:
       ```bash
       sudo apt update && sudo apt upgrade -y && sudo reboot
       ```
     - Install Elastic Stack and all other components, going <a href="https://www.elastic.co/downloads/elasticsearch">here</a> and choosing the "**deb x86_64**" platform and wright click on that and choose the option "**copy link address**" and run the following command:
       ```bash
       wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.15.3-amd64.deb

       dpkg -i elasticsearch-8.15.3-amd64.deb
       ```

After the installation has ended up, make sure to copy the output that will be printed, there are some important information, including the password of the admin user (elastic) of the Elastic Stack.

After that, open and modify the file /etc/elasticsearch/elasticsearch.yml, uncommenting the lines "**cluster.name:, network.host: and http.port:**" acording to the values of your environment.

       ```bash
       vi /etc/elasticsearch/elasticsearch.yml
       ```

After that, start the elasticsearch and check its status with the following commands:

       ```bash
       systemctl daemon-reload

       systemctl enable elasticsearch.service

       systemctl start elasticsearch.service

       systemctl status elasticsearch.service
       ```

   - **5.5: Setting up Kibana on Ubuntu Server 24.04 LTS**

     - After logging into the server, update the package manager:
       ```bash
       sudo apt update && sudo apt upgrade -y && sudo reboot
       ```
     - Install Kibana and all other components, going <a href="https://www.elastic.co/downloads/kibana">here</a> and choosing the "**DEB x86_64**" platform and wright click on that and choose the option "**copy link address**" and run the following command:
       ```bash
       wget https://artifacts.elastic.co/downloads/kibana/kibana-8.15.3-amd64.deb
       
       dpkg -i kibana-8.15.3-amd64.deb
       ```

After that, open and modify the file /etc/kibana/kibana.yml, uncommenting the lines "**server.port: and server.host::**" acording to the values of your environment.

       ```bash
       vi /etc/kibana/kibana.yml
       ```

After that, start the kibana service and check its status with the following commands:

       ```bash
       systemctl daemon-reload

       systemctl enable kibana.service

       systemctl start kibana.service

       systemctl status kibana.service
       ```

After all that, let us generate the enrollment token for kibana in the elasticsearch, running the following command:

       ```bash
       /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana
       ```

Copy the output to paste it when logging in on the web gui of the elastic. Go to your browser and type "**http://YOUR_KIBANA_IP:5601**", paste the output copied in the step before. You will be asked a verification code, just run the following command in the kibana machine:

       ```bash
       /usr/share/kibana/bin/kibana-verification-code
       ```

After all has runned well, it's time to generate the encryption keys for the API integration, run the following command:

       ```bash
       /usr/share/kibana/bin/kibana-encryption-keys generate
       ```

Copy and save the output generated, then run the following commands:

       ```bash
       /usr/share/kibana/bin/kibana-keystore add xpack.encryptedSavedObjects.encryptionKey
       ```

And paste the output on front of "**xpack.encryptedSavedObjects.encryptionKey**"

       ```bash
       /usr/share/kibana/bin/kibana-keystore add xpack.reporting.encryptionKey
       ```

And paste the output on front of "**xpack.reporting.encryptionKey**"

       ```bash
       /usr/share/kibana/bin/kibana-keystore add xpack.security.encryptionKey
       ```

And paste the output on front of "**xpack.security.encryptionKey**"

Restart kibana

       ```bash
       systemctl restart kibana.service
       ```

If you desire, you can change the elastic superuser password with the command bellow

       ```bash
       /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -i
       ```

   - **5.6: Setting up Fleet Server on Ubuntu Server 24.04 LTS**

     - After logging into the server, update the package manager:
       ```bash
       sudo apt update && sudo apt upgrade -y && sudo reboot
       ```
     - Install Suricata - It's important to use the OISF Personal Package Archives (PPA) because OISF maintains a PPA **suricata-stable** that always contains the latest stable release of Suricata:
       ```bash
       sudo apt install software-properties-common
       sudo add-apt-repository ppa:oisf/suricata-stable
       sudo apt update && sudo apt upgrade -y
       sudo apt install suricata jq -y
       ```

     - Enable and start Suricata:
       ```bash
       sudo systemctl enable suricata.service
       sudo systemctl start suricata.service
       ```

     - Create **rules** directory, download the Suricata rules to that directory and extract them:
       ```bash
       cd /tmp/ && curl -LO https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.tar.gz
       sudo tar -xvzf emerging.rules.tar.gz && sudo mkdir /etc/suricata/rules && sudo mv rules/*.rules /etc/suricata/rules/
       sudo chmod 640 /etc/suricata/rules/*.rules
       ```

     - Edit the Suricata settings in the **/etc/suricata/suricata.yaml** file and set the following variables accordingly:
       ```bash
       HOME_NET: "<YOUR_MACHINE_IP>"
       EXTERNAL_NET: "any"

       default-rule-path: /etc/suricata/rules
       rule-files:
       - "*.rules"

       # Global stats configuration
       stats:
       enabled: yes

       # Linux high speed capture support
       af-packet:
       - interface: enp0s3
       ```

     - Restart and check the status of Suricata service:
       ```bash
       sudo systemctl restart suricata.service
       sudo systemctl status suricata.service
       ```

   - **5.6: Add the following code inside the file */var/ossec/etc/ossec.conf* on Wazuh agent**

       ```bash
       <ossec_config>
         <localfile>
           <log_format>json</log_format>
           <location>/var/log/suricata/eve.json</location>
         </localfile>
       </ossec_config>
       ```

- Restart Wazuh agent

       ```bash
       sudo systemctl restart wazuh-agent
       ```

To check whether our configuration are working or no, we open one machine with NMAP installed and run the command below, then we check if that scan will be triggered.
     
       ```bash
       nmap -A 192.168.10.4
       ```

As can be seen on the image below, the scan was triggered

<p align="center">
<img width="812" alt="Scan triggered" src="https://github.com/user-attachments/assets/b045789e-441b-4f99-906f-b757d2f6c5a4">
</p>


### 6. **Conclusion**
   - This project successfully demonstrated:
   - The Suricata installation on Ubuntu Server 24.04 LTS and its configuration to detect anomalies on the server traffic;
   - The Wazuh installation on Ubuntu Server 24.04 LTS;
   - The Wazuh and Suricata integration and detected nmap scans with them both.


### 7. **Contact Information**
   - **Name**: Rogério Muhate
   - **Email**: rbmuhate@gmail.com
   - **LinkedIn**: [LinkedIn Profile](https://www.linkedin.com/in/rmuhate)
