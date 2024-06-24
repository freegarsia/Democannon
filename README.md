# Democannon
A Project for LG24Security Edu.

## Instructions

### Prerequisites

1. **Install vcpkg for Visual Studio package management**
   - A. Clone vcpkg repository: `git clone https://github.com/microsoft/vcpkg.git`
   - B. Navigate to vcpkg directory: `cd vcpkg`
   - C. Run bootstrap script: `bootstrap-vcpkg.bat`

2. **Visual Studio 2022 Configuration**
   - A. Add include folder:
     - `Configuration Properties > C/C++ > General > Additional Include Directories`: vcpkg Installation Path
   - B. Add lib folder:
     - `Configuration Properties > Linker > General > Additional Library Directories`: vcpkg Installation Path

### General Procedure

#### I. Setup

1. **Install Packages and Libraries for Client**
   - **OpenCV Installation:**
     - a) Download and Extract OpenCV:
       - Download OpenCV 4.9.0 from [official website](https://opencv.org/releases/).
       - Extract the ZIP file to `C:\opencv`.
     - b) Set Environment Variable:
       - Add `C:\opencv\build\x64\vc16` to the system environment variable `Path`:
         - Edit the `Path` variable in Windows Environment Variables.
         - Add `%OPENCV_DIR%\bin` to `Path` and set `OPENCV_DIR` as a system variable.
     - c) Configure Linker in Visual Studio 2022:
       - Open your project in Visual Studio 2022.
       - Go to `Project > Properties > Configuration Properties > VC++ Directories > Include Directories`.
         - Add `C:\opencv\build\include`.
       - Go to `Project > Properties > Configuration Properties > VC++ Directories > Library Directories`.
         - Add `C:\opencv\build\x64\vc16\lib`.
       - Go to `Project > Properties > Configuration Properties > Linker > Input > Additional Dependencies`.
         - Add:
           - Debug mode: `opencv_world490d.lib`
           - Release mode: `opencv_world490.lib`

   - **Install Visual Studio Packages: Cryptopp, spdlog, openssl**
     ```shell
     $ vcpkg search cryptopp
     $ vcpkg install cryptopp
     $ vcpkg integrate install
     ```

#### II. How to Build

1. **Compile for Client**
   - No special instructions.

2. **Compile for Server**
   - Provide specific instructions if any.

#### III. How to Run

   - Add instructions for running the application.

#### IV. Local Testing

1. **Password Constraints**
   - Size should be between 10 and 15 characters.
   - Must include at least 1 symbol and 1 number.
   - Blank spaces are not permitted.
   - Permitted symbols: !@#$%^&*()_+

## Documentation

- Design documentation: Check "Design&Requirement Documentation.pdf"
- Requirements documentation: Check "Design&Requirement Documentation.pdf"
