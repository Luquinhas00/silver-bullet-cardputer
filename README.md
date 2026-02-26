🎯 Silver Bullet - M5 Cardputer (ESP32-S3)

Uma ferramenta avançada de injeção de pacotes Wi-Fi Raw (Layer 2, Layer 3 e Layer 4) desenvolvida em C++ nativo para o ecossistema ESP-IDF. Focada em testes de estresse, análise de infraestrutura e estudos de segurança ofensiva, esta ferramenta testa o limite absoluto de equipamentos de rede, desde roteadores domésticos até hardware corporativo de provedores.

O Silver Bullet foi otimizado exclusivamente para o hardware do M5Stack Cardputer, extraindo o máximo da arquitetura Dual-Core do ESP32-S3. Com alocação direta de memória DMA, execução na SRAM e um Módulo de Inteligência Automática (Smart Auto-Sense), a ferramenta atua diretamente na camada física (PHY) e no Kernel do roteador alvo com perda de ciclos nula.
⚠️ Aviso Legal e Ético

Esta ferramenta foi criada estritamente para fins educacionais e testes de segurança em redes próprias ou com autorização explícita (Laboratórios de Pentest e Auditoria de Infraestrutura). A injeção de pacotes malformados e inundações de rede podem causar Kernel Panic, esgotamento de RAM e Negação de Serviço (DoS) severa em equipamentos. O uso deste software em redes de terceiros sem consentimento é ilegal e pode acarretar penalidades criminais. O autor não se responsabiliza pelo mau uso desta ferramenta.
⚙️ Funcionalidades Avançadas e Táticas Letais

Nesta versão, o código foi completamente refatorado para operar no limite físico do silício a 240MHz, incorporando as seguintes mecânicas de esgotamento:

    🤖 Smart Auto-Sense (Inteligência Tática): Analisa o protocolo de segurança do alvo em tempo real. Se o alvo usar WPA3 ou PMF (Protected Management Frames), a ferramenta descarta pacotes Deauth inúteis e adapta automaticamente a estratégia para focar no bloqueio de RF (CTS) e travamento de CPU (NAT Exhaustion).

    🔥 L4 NAT Meltdown (Derruba 2.4GHz e 5GHz simultaneamente): Forja pacotes UDP massivos com IPs públicos e portas aleatórias. Obriga o roteador a abrir milhares de sessões NAT por segundo, esgotando a tabela de roteamento e travando a CPU. Como a rede 5GHz partilha o mesmo Kernel, ela também entra em colapso.

    📻 CTS Jamming Físico: Injeção de quadros Clear-To-Send (duration = 32767µs), enganando o protocolo CSMA/CA e forçando todos os rádios no canal a silenciarem fisicamente, contornando proteções WPA3.

    👻 Beacon Flooding (Poluição de Espectro): Cria dezenas de redes Wi-Fi fantasmas por segundo com SSIDs dinâmicos, causando travamento no NetworkManager de clientes (PCs, Smart TVs, Smartphones) que tentem escanear o ambiente.

    🌡️ Proteção Térmica do Silício (Thermal Throttling): Monitoramento contínuo do sensor interno de temperatura do ESP32-S3. Se a pastilha ultrapassar os 75ºC devido ao rádio em potência máxima (20dBm), o sistema entra automaticamente em modo ECO (10dBm) para evitar degradação do hardware.

    🚀 Zero-Copy DMA & Variable Payload: Estruturas de pacotes alocadas nativamente em MALLOC_CAP_DMA. O tamanho do payload injetado muda a cada microssegundo, causando fragmentação letal no Garbage Collector (RAM) do roteador.

    📊 Telemetria LetaL: Cálculo matemático preciso de Pacotes Por Segundo (PPS) exibido em tempo real na tela.

🎮 Controles do Cardputer (Menu Tático)

O Silver Bullet permite isolamento de carga. Você pode focar todo o poder de fogo (PPS) em um único gargalo do roteador pressionando as teclas do Cardputer em tempo real durante o ataque:

    ENTER : Trava no alvo e inicia o ataque (Padrão: Automático).

    A : Reativa o Módulo de Inteligência Automática (Auto-Sense).

    1 : Override L2 (Foco em CAM Flooding / Deauth + Auth).

    2 : Override L3/L4 (Foco no Roteador - NAT/CPU Meltdown).

    3 : Override CTS (Foco Físico - RF Jamming CSMA/CA).

    4 : Override BEACON (Foco nos Clientes - Phantom APs).

    ESPAÇO : Alterna a potência da antena entre MAX (20dBm) e ECO (10dBm).

    BACKSPACE : Interrompe o ataque e volta ao scanner.

🏗️ Arquitetura Dual-Core (Thread-Safe)

O sistema foi desenhado para evitar que o peso da injeção de pacotes congele a interface:

    Core 0 (Motor de Injeção LetaL): Dedicado exclusivamente à task_ataque. Lê a variável atômica do Módulo de Inteligência e dispara as rajadas DMA.

    Core 1 (Radar, Inteligência e UI): Abriga a telemetria, análise térmica, leitura de teclado e o Smart Target Tracking. Se o roteador alvo tentar fugir mudando de canal (Auto-Channel), o Core 1 rastreia a mudança em background e realinha a mira sem que o Core 0 pare de atirar.

🛠️ Requisitos e Compilação (Arch Linux)

    Hardware: M5Stack Cardputer (M5Stamp S3).

    Framework: ESP-IDF v5.x (via Git). Nota: Incompatível com a IDE do Arduino devido ao uso bare-metal das APIs do rádio.

    Dependências do Projeto: m5stack/m5unified (gerenciado automaticamente via IDF Component Manager).

1. Instalar Dependências do Sistema

Abra o terminal e instale os pacotes necessários para compilação cruzada do ESP32:
Bash

sudo pacman -S --needed gcc git make cmake gperf python-pip python-setuptools python-wheel ninja flex bison

2. Configurar o ESP-IDF

Siga o guia oficial da Espressif para clonar e instalar o ESP-IDF no seu ambiente.
3. Ajuste Crítico do sdkconfig (MUITO IMPORTANTE)

Para que a alocação DMA funcione com a agressividade exigida por este código (causando o erro ESP_ERR_NO_MEM sob controle), você deve expandir a fila de pacotes dinâmicos do rádio.
No diretório do projeto, execute idf.py menuconfig e navegue até:
Component config ➔ Wi-Fi ➔ Max number of dynamic TX buffers.

    Altere o valor de 32 para 128.

4. Compilar e Gravar no Cardputer

Com o ambiente IDF exportado (. $HOME/esp/esp-idf/export.sh), compile e envie para o Cardputer via terminal:
Bash

idf.py build flash monitor