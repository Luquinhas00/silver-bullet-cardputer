# 🎯 Silver Bullet - M5 Cardputer (ESP32-S3)

Uma ferramenta avançada de injeção de pacotes Wi-Fi *Raw* (Layer 2 e Layer 3) desenvolvida em C++ nativo para o ecossistema ESP-IDF, focada em testes de estresse, análise de infraestrutura e estudos de segurança ofensiva.

O **Silver Bullet** foi otimizado exclusivamente para o hardware do **M5Stack Cardputer**, extraindo o máximo da arquitetura Dual-Core do ESP32-S3 para realizar ataques persistentes e monitoramento em tempo real de forma assíncrona.

---

> ⚠️ **Aviso Legal e Ético**
> 
> Esta ferramenta foi criada **estritamente para fins educacionais e testes de segurança em redes próprias** ou com autorização explícita (Laboratórios de Pentest). A injeção de pacotes malformados (como ataques *Teardrop* ou anomalias de fragmentação) e inundações de rede podem causar *Kernel Panic* e Negação de Serviço (DoS) em roteadores e equipamentos de infraestrutura. O uso deste software em redes de terceiros sem consentimento é ilegal e pode acarretar penalidades criminais. O autor não se responsabiliza pelo mau uso desta ferramenta.

---

## ⚙️ Funcionalidades Avançadas

* 📡 **Radar Passivo de Precisão:** Escaneamento do espectro 2.4 GHz para mapeamento de BSSIDs, SSIDs e canais, sem necessidade de associação.
* ⚔️ **Ataque Híbrido (Dual-Layer):** Injeção simultânea de quadros de *Deauthentication* (Layer 2) para desconectar clientes, e pacotes de Fragmentação IP malformados (Layer 3) para estressar os buffers de hardware do roteador.
* 🎯 **Smart Target Tracking:** Algoritmo executado em *background* no segundo núcleo (Core 1) que rastreia o alvo automaticamente caso ele altere o canal (*Auto-Channel*), mantendo a mira travada sem intervenção manual.
* 📊 **Monitoramento em Tempo Real:** Interface *standalone* com exibição gráfica da força do sinal (RSSI) e voltagem da bateria, isolada do loop de ataque para não gargalar a injeção.
* 🚀 **Otimização de Hardware:** Construído para operar com a CPU a 240MHz, buffers de TX Wi-Fi expandidos e contorno de proteções de *Watchdog* para evitar interrupções em operações de alta densidade.

---

## 🛠️ Requisitos de Hardware e Software

* **Hardware:** M5Stack Cardputer (M5Stamp S3).
* **Sistema Operacional (Dev):** Arch Linux (ou derivados) recomendado.
* **Framework:** ESP-IDF v5.x (via Git). *Nota: Não é compatível com a IDE do Arduino devido à necessidade de acesso de baixo nível às APIs do rádio Wi-Fi.*
* **Dependências:** `m5stack/m5unified` (gerenciado automaticamente via IDF Component Manager).

---

## 🚀 Guia de Instalação e Compilação (Arch Linux)

### 1. Instalar Dependências do Sistema
Abra o terminal e instale os pacotes necessários para compilação cruzada do ESP32:
```bash
sudo pacman -S --needed gcc git make cmake gperf python-pip python-setuptools python-wheel ninja flex bison