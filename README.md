# 🎯 Silver Bullet - M5 Cardputer (ESP32-S3)

Uma ferramenta de injeção de pacotes Wi-Fi *Raw* (Layer 2 e Layer 3) desenvolvida em C++ nativo para o ecossistema ESP-IDF, focada em testes de estresse, análise de infraestrutura e estudos de segurança ofensiva.

Desenvolvido exclusivamente para o hardware do **M5Stack Cardputer** (arquitetura ESP32-S3).

---

## ⚠️ Aviso Legal e Ético
**Esta ferramenta foi criada estritamente para fins educacionais e testes de segurança em redes próprias ou com autorização explícita (Laboratórios de Pentest).** A injeção de pacotes malformados (como ataques *Teardrop* ou anomalias de fragmentação) e inundações de rede podem causar *Kernel Panic* e Negação de Serviço (DoS) em roteadores e equipamentos de infraestrutura. O uso deste software em redes de terceiros sem consentimento é ilegal. O autor não se responsabiliza pelo mau uso desta ferramenta.

---

## ⚙️ Funcionalidades Principais
* **Radar Passivo (Scanner):** Escaneamento ativo do espectro 2.4 GHz para mapeamento de BSSIDs, SSIDs e Canais sem necessidade de associação.
* **Injeção Raw (Modo Promíscuo):** Utiliza as APIs de baixo nível da Espressif (`esp_wifi_80211_tx`) para disparar pacotes forjados diretamente na antena.
* **Manipulação de Camadas (L2/L3):** Estruturas (`structs`) personalizadas em C++ para forjar cabeçalhos MAC (Spoofing) e IPv4 diretamente na memória.
* **Interface Standalone:** Controle total via tela LCD e teclado matricial do Cardputer (usando M5Unified/M5Cardputer), sem necessidade de cabo serial após a gravação.

---

## 🛠️ Requisitos de Hardware e Software
* **Hardware:** M5Stack Cardputer (M5Stamp S3).
* **Framework:** ESP-IDF v5.x (Não compatível com a IDE padrão do Arduino devido ao acesso de baixo nível do rádio).
* **Dependências:** `m5stack/m5unified` (gerenciado via IDF Component Manager).

---

## 🚀 Como Compilar e Instalar (Linux/Arch)

1. **Clone o repositório:**
   ```bash
   git clone [https://github.com/Luquinhas00/silver-bullet-cardputer.git](https://github.com/Luquinhas00/silver-bullet-cardputer.git)
   cd silver-bullet-cardputer
