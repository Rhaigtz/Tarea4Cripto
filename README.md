### **Consideraciones importantes**

---

- En el comando system.os() esta la ruta de la carpeta hashcat de mi local por lo que si el hashcat se encuentra en otra posicion se debe cambiar la ruta.
- Dentro de la carpeta de hashcat esta la carpeta con los Hashes y diccionarios, aplica lo mismo de arriba, deben dejarse estas carpetas en la del hashcat.
- El archivo de salida esta una carpeta atras de la del hashcat, aplica lo mismo debe cambiarse
- Si ya existen los archivos .sqlite deben ser eliminados debido a que sino dara error.
- La carpeta hashed contiene los archivos hasheados con bcrypt
- La carpeta output contiene el output de hashcat
- La carpeta rehashed contiene los archivos encriptados con RSA_OAEP
- La carpeta unhashed contiene los archivos des-encriptados de RSA_OAEP
