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

After upgrading and rebooting the system, go to your kibana web GUI and follow the steps indicated in the image below.

<p align="center">
<img width="955" alt="Fleet Server installation" src="https://github.com/user-attachments/assets/7e52549e-711b-485b-820f-9e9cf50981f7">
</p>

After clicking the "**Add Fleet Server**" button, fill the form presented in the right side, as the image below shows. The IP to be filled is the fleet server one.

<p align="center">
<img width="944" alt="Fleet Server installation - fill the details of the fleet server" src="https://github.com/user-attachments/assets/0f3b494a-c51f-424d-a5f7-6301c4ce6816">
</p>

After generating the fleet server policy, copy the command presented in the next screen, as showed in the image below. Make sure to add the flag "**--insecure**" before running the command omn the fleet server.

<p align="center">
<img width="944" alt="Command to copy for fleet server installation" src="https://github.com/user-attachments/assets/93185a02-8ce3-4c13-abab-64b5c6673791">
</p>

If everything runs well, the button ""**Continue enrolling Elastic Agent**"" will become clickable, click on that and continue.

<p align="center">
<img width="944" alt="Continue enrolling Elastic Agent" src="https://github.com/user-attachments/assets/a3a2cc80-bb6e-48d2-a54a-88b079e8bf18">
</p>

- **5.7: Setting up Fleet Agent on Windows Server 2022**

After everything has run well, it's time to add some agents. We are going to start by adding on Windows machine, so follow the steps showed in the image below:

<p align="center">
<img width="944" alt="Add Agent" src="https://github.com/user-attachments/assets/0f880b3e-d075-4a64-9c1f-6401e55aa467">
</p>

Another screen will be opened, fill the policy name, in this case we create the windows policy. This is a good practice, as for each OS we are going to have a diferrent policy.

<p align="center">
<img width="944" alt="Windows Policy creation" src="https://github.com/user-attachments/assets/f509c73b-6090-4f95-b812-8a657e58d775">
</p>

As we are installing the agent in a Windows OS, we choose Windows ""**Install Elastic Agent on you host**"" and copy the command to run on the Windows machine. Make sure to add the flag ""**--insecure**"" before running the command. Run the command as Administrator in the PowerShell.

<p align="center">
<img width="944" alt="Command to run on Windows machine" src="https://github.com/user-attachments/assets/cd2f38a5-72e8-4ce6-b04b-6970dc8d2e70">
</p>

- **5.8: Setting up Sysmon on Windows Server 2022**

To setup sysmon on Windows, we need first to download, extract and install the sysmon with its configuration file. To download sysmon, go <a href="https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon">here</a>, download the executable for windows and extract it, then go <a href="https://github.com/olafhartong/sysmon-modular/blob/master/sysmonconfig.xml">here</a> to download the Olaf configuration file. Make sure to save inside the folder created when extracting sysmony. Open PowerShell and navigate to the sysmon extracted folder and run the following command:

       ```bash
       .\Sysmon64.exe -i sysmonconfig.xml --accepteula
       ```

- **5.8: Setting up Fleet Agent on Ubuntu Server 24.04**

To add the agent on Ubuntu Server we follow the same steps taken to add it on Windows Server, but we will create another policy for Linux servers. So click the "**Add agent**" button, as shown in the image below.

<p align="center">
<img width="944" alt="Agent addition" src="https://github.com/user-attachments/assets/1a8592eb-5e52-4819-81e3-9ff235c3be6c">
</p>

Then create new policy, by clicking the "**Create new agent policy**" button

<p align="center">
<img width="944" alt="Create new agent policy" src="https://github.com/user-attachments/assets/61265e17-7255-4d05-8dca-f3127bca66f7">
</p>

You will be prompted with a screen to fill the name of the new policy, just give a name for that and click "**Create policy**" button, as shown below

<p align="center">
<img width="944" alt="Policy creation" src="https://github.com/user-attachments/assets/be3130be-30d8-4c90-85cb-6014309810fc">
</p>

As we are installing the agent in a Linux (Ubuntu) OS, we choose "**Linux Tar**" inside "**Install Elastic Agent on you host**" and copy the command to run on the Linux machine. Make sure to add the flag ""**--insecure**"" before running the command. Run the command as root user in the command line.

<p align="center">
<img width="944" alt="Command to run on Linux machine" src="https://github.com/user-attachments/assets/1f95e16a-37c0-4d77-8031-8dcf8441acc5">
</p>

- **6: Ingest logs to Elastic Stack**

To ingest logs to Elastic Stack we will need to add some integrastions to our agents. We are going to start with the agents installed on the Windows machine. We'll be adding the integrations through the policies, so that the integrations are added to all the agents enrolled on that policy. Follow the steps in the image below to add integrations.


<p align="center">
<img width="944" alt="Add integration" src="https://github.com/user-attachments/assets/d8e0d5c4-c3e8-4c9b-9dcc-cce141c81554">
</p>

We search for the term "**Windows**" and we can choose between "**Custom Windows Event Logs**" and "**windows**". In this project we are going to choose the first, as shown in the image below:

<p align="center">
<img width="944" alt="Custom Windows Event Logs integration" src="https://github.com/user-attachments/assets/57ebd370-582e-41b1-aaad-258079dbfec2">
</p>




### 7. **Conclusion**
   - This project successfully demonstrated:
   - The Suricata installation on Ubuntu Server 24.04 LTS and its configuration to detect anomalies on the server traffic;
   - The Wazuh installation on Ubuntu Server 24.04 LTS;
   - The Wazuh and Suricata integration and detected nmap scans with them both.


### 7. **Contact Information**
   - **Name**: Rogério Muhate
   - **Email**: rbmuhate@gmail.com
   - **LinkedIn**: [LinkedIn Profile](https://www.linkedin.com/in/rmuhate)
