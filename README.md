<<<<<<< HEAD
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
=======
🎯 Silver Bullet - M5 Cardputer (ESP32-S3)

Uma ferramenta de injeção de pacotes Wi-Fi Raw (Layer 2 e Layer 3) desenvolvida em C++ nativo para o ecossistema ESP-IDF, focada em testes de estresse, análise de infraestrutura e estudos de segurança ofensiva.

O Silver Bullet foi otimizado exclusivamente para o hardware do M5Stack Cardputer, extraindo o máximo da arquitetura Dual-Core do ESP32-S3 para realizar ataques persistentes e monitoramento em tempo real.
⚠️ Aviso Legal e Ético

Esta ferramenta foi criada estritamente para fins educacionais e testes de segurança em redes próprias. O autor não se responsabiliza pelo mau uso deste software. O uso em redes de terceiros sem consentimento explícito é ilegal e pode acarretar penalidades criminais.
⚙️ Funcionalidades Avançadas

    Radar Passivo de Precisão: Escaneamento ativo do espectro 2.4 GHz para mapeamento de BSSIDs e canais.

    Ataque Híbrido (Dual-Layer): Injeção simultânea de quadros de Deauthentication (Layer 2) para desconectar clientes e pacotes de Fragmentação IP malformados (Layer 3) para estressar o buffer do roteador.

    Smart Target Tracking: Algoritmo executado no segundo núcleo (Core 1) que rastreia automaticamente o alvo caso ele altere o canal (Auto-Channel), mantendo a mira travada sem intervenção manual.

    Monitoramento em Tempo Real: Exibição gráfica da força do sinal (RSSI) e monitor de voltagem da bateria para operações móveis.

    Otimização de Hardware: Configurado para operar em 240MHz com buffers Wi-Fi expandidos e Watchdogs desativados para evitar interrupções em loops de alta densidade.

🛠️ Requisitos de Sistema (Linux/Arch)

    Hardware: M5Stack Cardputer.

    OS: Arch Linux (ou derivados).

    Framework: ESP-IDF v5.x (via Git).

🚀 Guia de Instalação Detalhado
1. Instalar Dependências do Sistema

Abra o terminal e instale os pacotes necessários para o desenvolvimento com ESP32:
Bash

sudo pacman -S --needed gcc git make cmake gperf python-pip python-setuptools python-wheel ninja flex bison gperf

2. Configurar o ESP-IDF (Ambiente de Desenvolvimento)

Recomendamos a instalação na pasta ~/esp:
Bash

mkdir -p ~/esp
cd ~/esp
git clone --recursive https://github.com/espressif/esp-idf.git
cd esp-idf
./install.sh esp32s3

3. Clonar o Projeto e Preparar o Build
Bash

cd ~/esp
git clone https://github.com/Luquinhas00/silver-bullet-cardputer.git
cd silver-bullet-cardputer

4. Ativar o Ambiente e Configurar Hardware

Sempre que abrir um novo terminal, você deve exportar as variáveis do IDF:
Bash

. ~/esp/esp-idf/export.sh

Configuração Crítica (Menuconfig):
Para garantir que o código funcione com a potência total, execute:
Bash

idf.py menuconfig

Navegue e altere:

    Component config → ESP System Settings:

        CPU Frequency → 240 MHz

        Initialize Interrupt Watchdog → Desativar

        Initialize Task Watchdog → Desativar

    Component config → Wi-Fi:

        WiFi dynamic TX buffer number → 128

Salve (S) e Saia (Q).
5. Compilar e Gravar

Conecte o seu Cardputer via USB e execute:
Bash

idf.py build
idf.py -p /dev/ttyUSB0 flash monitor

(Substitua /dev/ttyUSB0 pela porta correta do seu dispositivo, geralmente listada com ls /dev/ttyUSB*)
🎮 Instruções de Uso

    Radar: Ao ligar, a ferramenta inicia o radar automaticamente.

    Seleção: Use as setas UP/DOWN do teclado do Cardputer para navegar entre as redes encontradas.

    Ataque: Pressione ENTER para travar a mira. A tela mudará para o modo de ataque híbrido.

    Monitor: Verifique a barra de sinal e a bateria. Se o alvo mudar de canal, o rastreador inteligente atualizará a frequência em segundos.

    Abortar: Pressione BACKSPACE para parar o ataque e voltar ao radar.

📦 Estrutura do Repositório

    main/silver_bullet.cpp: Núcleo do sistema de injeção e lógica de rastreio.

    main/idf_component.yml: Gerenciamento de dependências (M5Unified).

    sdkconfig.defaults: Configurações de partição para suportar apps grandes.

Desenvolvido por Lucas Ferrari Dúvidas ou sugestões? Sinta-se à vontade para abrir uma Issue ou contribuir com o código!
>>>>>>> 46a8a97 (Implementação final: Smart Tracking, Ataque Híbrido e Documentação)
