[![Generic badge](https://img.shields.io/badge/Maturity-Experimental-red.svg)
](#)
[![Generic badge](https://img.shields.io/badge/Python-3.7–3.11-blue.svg)](#)
[![Generic badge](https://img.shields.io/badge/OS-Linux%20|%20macOS%20-blue.svg)](#)

# [Rubberhose FUSE File System](https://github.com/rtmigo/dmk_py#readme)

**ESTE ES UN CÓDIGO EXPERIMENTAL. EL FORMATO DEL ARCHIVO PUEDE CAMBIAR**

Rubberhose.py es una herramienta para crear un sistema de archivos FUSE con denegación plausible. Permite almacenar y recuperar archivos cifrados en múltiples entornos ocultos y añadir datos aleatorios para mejorar la seguridad.

# 

## Características
- Creación de un contenedor para albergar de sistema de archivos FUSE cifrado.
- Creación de múltiples sistemas de archivos con múltiples claves diferentes para proporcionar negación plausible.
- Un entorno común para tener ficheros señuelo que puedan ayudar a convencer a un adversario que no existen sistemas de archivos ocultos.
- Todos los ficheros se encuetran cifrados y son indistinguibles de datos aleatorios.
- Inserción de datos aleatorios para reforzar la denegación plausible.
- Montaje del sistema de archivos FUSE.
- Integridad en todos los ficheros.
- Eliminación segura de ficheros.
- Resistencia a análisis diferenciales.

## Instalación

Para ejecutar `rubberhose.py`, asegúrate de tener instalado Python y las dependencias necesarias.

```sh
pip install -r requirements.txt
```

## Uso

```sh
python rubberhose.py [-h] [-f FILE] [-s SIZE] [-o OUTFILE] [-i INPUTFILE] {init,getfile,setfile,fuse,random} ...
```

### Argumentos Posicionales

- `init` → Inicializa el contenedor del sistema de archivos FUSE.
- `getfile` → Recupera un archivo cifrado de un entorno.
- `setfile` → Guarda un archivo cifrado en un entorno.
- `fuse` → Monta el sistema de archivos FUSE.
- `random` → Inserta datos aleatorios en el contenedor.

### Argumentos Opcionales

- `-h, --help` → Muestra la ayuda del programa y sale.
- `-f FILE, --file FILE` → Ruta del archivo a procesar.
- `-s SIZE, --size SIZE` → Tamaño de los datos aleatorios a insertar en bytes.
- `-o OUTFILE, --outfile OUTFILE` → Ruta del archivo de salida.
- `-i INPUTFILE, --inputfile INPUTFILE` → Ruta del archivo de entrada.

## Ejemplos de Uso

### Inicializar un contenedor FUSE
```sh
python rubberhose.py init -f container.bin -s 100M
```

### Guardar un archivo cifrado en el entorno
```sh
python rubberhose.py setfile -i secreto.txt -f container.bin
```

### Recuperar un archivo cifrado
```sh
python rubberhose.py getfile -o recuperado.txt -f container.bin
```

### Montar el sistema de archivos
```sh
python rubberhose.py fuse -f container.bin -r ./fuse -m /fuse
```

### Insertar datos aleatorios en el contenedor
```sh
python rubberhose.py random -s 10M -f container.bin
```

## Requisitos
- Python 3.x
- Sistema UNIX
- Librerías necesarias (ver `requirements.txt`)
- FUSE instalado en el sistema

## Licencia
Este proyecto está licenciado bajo la licencia MIT.

## Contribuciones
¡Las contribuciones son bienvenidas! Si deseas mejorar el proyecto, abre un issue o envía un pull request.

