# Democannon

# How to use Crypto++ library
* install Crypto++ via vcpkg
1. install vcpkg
  1) git clone https://github.com/microsoft/vcpkg.git
  2) cd vcpkg
  3) bootstrap-vcpkg.bat

2. install vcpkg
  1) vcpkg search cryptopp
  2) vcpkg install cryptopp
  3) vcpkg integrate install

3. Visual Studio 2022 config
  1) 구성 속성 > C/C++ > 일반 > 추가 포함 디렉터리: vcpkg 설치 경로 아래의 include 폴더를 추가합니다.
  2) 구성 속성 > 링커 > 일반 > 추가 라이브러리 디렉터리: vcpkg 설치 경로 아래의 lib 폴더를 추가합니다. 


