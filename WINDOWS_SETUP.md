# Windows Setup Guide (Java DPI Engine)

This guide will help you set up, build, and run the Java DPI Engine on Windows. 

Since the project has been fully ported to Java and includes Live Network Sniffing capabilities, you no longer need C++ compilers like Visual Studio or MinGW.

---

## Step 1: Install Java (JDK)

You need **Java 11** or higher. (Java 17 or Java 21 is recommended).

1. Download the latest JDK from Oracle or Adoptium:
   - [Adoptium Temurin (Free & Open Source)](https://adoptium.net/)
   - Download the `.msi` installer for Windows x64.
2. Run the installer. 
3. **Important**: During installation, make sure you check the box that says **"Set JAVA_HOME variable"** and **"Add to PATH"**.

## Step 2: Install Apache Maven

Maven is the build tool used to compile the Java project and package its dependencies.

1. Download Maven from: https://maven.apache.org/download.cgi
   - Download the `Binary zip archive` (e.g., `apache-maven-3.9.x-bin.zip`).
2. Extract the `.zip` file to a permanent location (e.g., `C:\Program Files\Apache\maven`).
3. Add Maven to your PATH:
   - Press `Win + R`, type `sysdm.cpl`, press Enter.
   - Go to the **"Advanced"** tab → **"Environment Variables"**.
   - Under "System variables", find **"Path"**, click **"Edit"**.
   - Click **"New"** and add the path to the Maven `bin` folder (e.g., `C:\Program Files\Apache\maven\bin`).
   - Click OK on all windows.
4. Verify installation: Open a new Command Prompt or PowerShell and type:
   ```cmd
   mvn -version
   ```

## Step 3: Install Npcap (Required for Live Sniffing)

To capture live packets directly from your network interface (Wi-Fi or Ethernet), the `Pcap4J` library requires the Npcap driver.

1. Download Npcap from: https://npcap.com/#download
2. Run the installer. 
   - Ensure the option **"Install Npcap in WinPcap API-compatible Mode"** is checked.
   *(Note: If you already have Wireshark installed, Npcap is likely already installed!)*

---

## Step 4: Build the Project

1. Open **Command Prompt** (cmd) or **PowerShell**.
2. Navigate to the `java_dpi` directory inside the project:
   ```cmd
   cd C:\path\to\Packet_analyzer-main\java_dpi
   ```
3. Run the Maven build command:
   ```cmd
   mvn clean package -DskipTests
   ```
4. If successful, you will see a `BUILD SUCCESS` message. The executable fat JAR will be created at: `target\dpi.jar`.

---

## Step 5: Run the Engine

You can run the engine in two modes: **Offline PCAP Analysis** or **Live Interface Sniffing**.

### Mode 1: Offline PCAP Analysis
Analyze an existing `.pcap` file and save the filtered output.

```cmd
java -jar target\dpi.jar ..\test_dpi.pcap output.pcap
```

### Mode 2: Live Network Sniffing
Capture and analyze traffic in real-time straight from your network card.

1. Find your network interface name by running:
   ```powershell
   Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object Name
   ```
   *(It will output something like "Wi-Fi" or "Ethernet")*

2. Run the engine with the `-i` flag:
   ```cmd
   java -jar target\dpi.jar -i "Wi-Fi"
   ```

### Blocking Rules Examples
You can append blocking rules to either mode:

```cmd
REM Block YouTube and Facebook
java -jar target\dpi.jar -i "Wi-Fi" --block-app YouTube --block-domain facebook

REM Block a specific IP (IPv4 or IPv6)
java -jar target\dpi.jar ..\test_dpi.pcap output.pcap --block-ip 192.168.1.50

REM Show verbose per-packet output
java -jar target\dpi.jar -i "Wi-Fi" --block-app Discord --verbose
```

---

## Troubleshooting

### Error: `'mvn' is not recognized`
**Cause:** Maven is not properly added to your system's PATH.
**Fix:** Double check Step 2. Make sure you restart your terminal after editing Environment Variables.

### Error: `No suitable driver found` or `UnsatisfiedLinkError` during Live Sniffing
**Cause:** Npcap is not installed, or installed incorrectly.
**Fix:** Download and reinstall Npcap (Step 3). Make sure WinPcap API-compatibility mode is enabled.

### Error: `java: command not found`
**Cause:** Java is not installed or not in PATH.
**Fix:** Follow Step 1 to install the Adoptium JDK.
