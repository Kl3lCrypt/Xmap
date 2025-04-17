# Xmap
Escaner de redes (ARP, ICMP, TCP)

## 📚 Descripción
Xmap es una herramienta de escaneo de redes desarrollada en Python, diseñada para ser rápida, sencilla de usar y con una salida visualmente atractiva mediante colores en la consola.

El escáner soporta los protocolos más comunes para el análisis de redes, incluyendo TCP, ICMP y ARP, lo que permite realizar exploraciones detalladas de dispositivos en la red.

Este proyecto fue creado para ofrecer una alternativa rápida y fácil de usar para la detección de dispositivos activos, todo mientras mantiene una sintaxis simple y clara para el usuario. Además, las salidas del escáner están optimizadas con colores en consola, facilitando la visualización de los resultados.

Características clave:

- Escaneo TCP: Detecta puertos abiertos en dispositivos dentro de una red.

- Escaneo ICMP: Realiza pings para identificar dispositivos activos en la red.

- Escaneo ARP: Permite identificar la relación entre direcciones IP y MAC en la red local.

- Salida visual en consola: Resultados detallados con colores para mejorar la legibilidad.

- Rápido y eficiente: Escaneo optimizado para un rendimiento rápido sin perder precisión.


## 🚀 Instalación

Instrucciones para instalar y poner en marcha el proyecto.

### Clonar el repositorio:
```bash
git clone https://github.com/tu-usuario/tu-repo.github
```

```bash
pip3 install require.txt
```

## Uso:

Instrucciones de uso.

# Scan ARP
```bash
./xmap -t 192.168.1.0/24 -s arp
```

# Scan ICMP
```bash
./xmap -t 192.168.1.1-254 -s icmp
```

# Scan TCP
```bash
./xmap -t 192.168.1.0/24 -s tcp
```




