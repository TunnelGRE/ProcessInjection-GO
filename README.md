# ProcessInjection-GO

Shellcode encrypted in RC4 and process injection into explorer.exe. Added the patch to etwEventWrite function in order to avoid ETW tracing.

Tested with metasploit shellcode and it bypass EDR. 



Encrypt your payload with RC4Encryptor.go and paste it on the main.



![CRT](https://user-images.githubusercontent.com/130594453/231800596-885cd1ff-0273-4c60-978e-6f164a18ec1f.PNG)
