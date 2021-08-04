# Reflective-DLL-Loader

- 동작 과정
- Embedded DLL 주소 가져온 뒤 PE 파싱
2. SizeOfImage만큼 새로운 공간 할당
3. Manual Mapping
4. PE Relocation
5. IAT Processing
6. DLL EntryPoint 호출
