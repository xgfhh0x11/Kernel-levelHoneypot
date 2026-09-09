# Building the Kernel-Level Honeypot

## Prerequisites

1. **Windows Driver Kit (WDK) 10**
   - Download from: https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk
   - Install Visual Studio 2019/2022 integration

2. **Visual Studio 2019/2022**
   - Community edition is sufficient
   - Install "Desktop development with C++" workload

3. **Windows SDK**
   - Usually included with Visual Studio
   - Version 10.0.19041.0 or later recommended

## Build Instructions

### Method 1: Using Visual Studio

1. Open Visual Studio
2. Create a new "Kernel Mode Driver, Empty (KMDF)" project
3. Add all source files from `KernelDriver/` directory
4. Configure project settings:
   - Platform: x64
   - Configuration: Release
   - Target OS Version: Windows 10
5. Build the solution

### Method 2: Using WDK Build Environment

1. Open "x64 Native Tools Command Prompt for VS 2019/2022"
2. Navigate to project directory:
   ```cmd
   cd C:\Users\tylersec\Desktop\Kernel-levelHoneypot\KernelDriver
   ```
3. Build using MSBuild:
   ```cmd
   msbuild /t:build /p:Configuration=Release /p:Platform=x64
   ```

### Method 3: Using WDK sources File

1. Open WDK build environment
2. Navigate to KernelDriver directory
3. Run:
   ```cmd
   build -cZ
   ```
   This uses the `sources` file for build configuration.

## Building User-Mode Application

1. Open Visual Studio
2. Create a new "Console App" project
3. Add `HoneyPotControl.c` and `HoneyPotControl.h`
4. Build in Release x64 configuration

Or use command line:
```cmd
cd UserModeApp
cl /Fe:HoneyPotControl.exe HoneyPotControl.c /link kernel32.lib user32.lib
```

## Installation

1. **Enable Test Signing** (required for unsigned drivers):
   ```cmd
   bcdedit /set testsigning on
   ```
   Reboot required.

2. **Copy driver to Release directory**:
   ```cmd
   mkdir C:\Release
   copy KernelDriver\x64\Release\FakeNetFilter.sys C:\Release\
   copy config\honey.conf C:\Release\
   ```

3. **Install driver**:
   ```cmd
   sc create FakeNetFilter binPath= "C:\Release\FakeNetFilter.sys" type= kernel
   sc start FakeNetFilter
   ```

4. **Verify installation**:
   ```cmd
   sc query FakeNetFilter
   ```

5. **Run control application**:
   ```cmd
   HoneyPotControl.exe
   ```

## Troubleshooting

### Driver fails to load
- Check Event Viewer for error details
- Verify test signing is enabled
- Ensure driver is built for correct architecture (x64)
- Check that all dependencies are available

### Cannot connect to driver
- Verify driver is running: `sc query FakeNetFilter`
- Check device name matches in code
- Ensure running as Administrator

### Build errors
- Verify WDK is properly installed
- Check Visual Studio integration
- Ensure all include paths are correct
- Verify target OS version compatibility

## Security Notes

⚠️ **WARNING**: This is a research/educational tool. 

- Do NOT use in production environments
- Do NOT deploy on systems with sensitive data
- Use only in isolated test environments
- The encryption implementation is simplified and NOT production-ready
- Some security features are placeholders

## Uninstallation

```cmd
sc stop FakeNetFilter
sc delete FakeNetFilter
bcdedit /set testsigning off
```

Reboot to disable test signing.

