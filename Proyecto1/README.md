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

### Errores
1. vfs_statfs -> "/":
    - Se debe a que el archivo que se intenta escribir no existe.
    - Se utilizo kern_path para obtener la estructura de la ruta y luego se utilizo vfs_statfs para obtener la informacion del sistema de archivos.

2. Memoria Swap
    - No lograba obtener la informacion de la memoria swap.
    - Despues de buscar en la documentacion de kernel.org, encontre que las funciones:
        - totalram_pages
        - get_nr_swap_pages
        - global_zone_page_state
    Me permitieron obtener la informacion de la memoria swap.
    

### Reflexión
Gran parte del codigo no es extensa, el codigo de cada syscall es menor a 20 lineas, pero lo mas complicado fue busca la informacion para saber que estructuras y funciones. Tambien el hecho de tener que compilar y reiniciar el kernel cada vez que se hacia un cambio en el codigo, lo cual hacia que el proceso de desarrollo fuera mas lento para detectar errores y realizar cambios.
