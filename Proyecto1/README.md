# Proyecto 1

### Instalación de dependencias
```bash
sudo apt-get install build-essential libncurses-dev bison flex libssl-dev libelf-dev
```

### Kernel
Descargar la versión 6.8.0 del kernel de Linux desde [kernel.org](https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.8.tar.xz) y descomprimir en el directorio raíz del proyecto.

### Compilación

En el directorio raíz del proyecto ejecutar:
```bash
cp -v /boot/config-$(uname -r) .config
```

Limpiar el ambiente de compilación:
```bash
make clean
```

Ejecutar los config iniciales:
```bash
make oldconfig
make localmodconfig
```

Deshabilitar los certificados de firma oficiales de Cannonical:
```bash
scripts/config --disable SYSTEM_TRUSTED_KEYS
scripts/config --disable SYSTEM_REVOCATION_KEYS
```

Ejecutar la compilación:
```bash
make -j$(nproc --ignore=1)
```

### Instalación

Instalar los módulos del kernel:
```bash
make modules_install
make instal
make headers_install
update-grub2
```

```
bash
ln -s /home/fernando/Documents/SOPES2/Proyecto1/kernel/fork.c ./
```