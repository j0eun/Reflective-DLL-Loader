# Reflective-DLL-Loader

- Embedded DLL

![image](https://user-images.githubusercontent.com/49597086/128273301-77312938-0816-479f-9c89-cc03ecd378b7.png)

리소스 영역에 "SHELLCODE"라는 이름으로 내장된 DLL. 메시지박스를 호출한다.


- 동작 과정

  1. Embedded DLL 주소 가져온 뒤 PE 파싱
  2. SizeOfImage만큼 새로운 공간 할당
  3. Manual Mapping
  4. PE Relocation
  5. IAT Processing
  6. DLL EntryPoint 호출
