# Democannon
A Project for LG24Security Edu.

## Instructions
### Prerequisites
1. instdall vcpkg for Visual Studio package management
  1) git clone https://github.com/microsoft/vcpkg.git
  2) cd vcpkg
  3) bootstrap-vcpkg.bat

2. Visual Studio 2022 config
  1) 구성 속성 > C/C++ > 일반 > 추가 포함 디렉터리: vcpkg 설치 경로 아래의 include 폴더를 추가합니다.
  2) 구성 속성 > 링커 > 일반 > 추가 라이브러리 디렉터리: vcpkg 설치 경로 아래의 lib 폴더를 추가합니다. 

### General Procedure
#### I. Setup
1. install packageas and librarys FOR Client
1) install OpenCV :
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


