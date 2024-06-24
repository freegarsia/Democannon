# Democannon
A Project for LG24Security Edu.

## Instructions
### Prerequisites
1. instdall vcpkg for Visual Studio package management
  1) git clone https://github.com/microsoft/vcpkg.git
  2) cd vcpkg
  3) bootstrap-vcpkg.bat

2. Visual Studio 2022 config
  1) Add the include folder under Configuration Properties > C/C++ > General > Include Add Directory: vcpkg Installation Path.
  2) Add a lib folder under Configuration Properties > Linkers > General > Additional Library Directory: vcpkg Installation Path.

### General Procedure
#### I. Setup
1. install packageas and librarys FOR Client
 1) install OpenCV :
     ## Environment Variable and Linker Setup for Visual Studio 2022
  a) **Download and Extract OpenCV:**
   - Download OpenCV 4.9.0 from the [official website](https://opencv.org/releases/).
   - Extract the ZIP file to `C:\opencv`.
  b) **Set Environment Variable:**
   - Add `C:\opencv\build\x64\vc16` to the system environment variable `Path`:
     - Search for "Edit the system environment variables" in Windows.
     - Open "Environment Variables".
     - Edit the `Path` variable and add opencv. ex) Path-%OPENCV_DIR%\bin , system variable-OPENCV_DIR
  c) **Configure Linker in Visual Studio 2022:**
   - Open your project in Visual Studio 2022.
   - Go to `Project > Properties > Configuration Properties > VC++ Directories > Include Directories`.
     - Add `C:\opencv\build\include`.
   - Go to `Project > Properties > Configuration Properties > VC++ Directories > Library Directories`.
     - Add `C:\opencv\build\x64\vc16\lib`.
   - Go to `Project > Properties > Configuration Properties > Linker > Input > Additional Dependencies`.
     - Add the following:
       - Debug mode: `opencv_world490d.lib`
       - Release mode: `opencv_world490.lib`

 2) install Visual Studio packages : Cryptopp, spdlog, openssl
  ```How to install
  $ vcpkg search cryptopp
  $ vcpkg install cryptopp
  $ vcpkg integrate install
  ```

#### II. How to build
1. How to compile for Client
   -> nothing special
2. How to compile for Server

#### III. How to run

#### IV. Local Testing
1. Password Constraints
 1) size should be 10 <= pw <= 15
 2) include at least 1 symbole and 1 number BUT blank is not permitted
 3) Permitted symbols : !@#$%^&*()_+


## Design documentation
Check "Design&Requirement Documentation.pdf"

## Requirements documentation
Check "Design&Requirement Documentation.pdf"


