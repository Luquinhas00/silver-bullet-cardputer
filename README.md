🎯 Silver Bullet - M5 Cardputer (ESP32-S3)

Uma ferramenta avançada de injeção de pacotes Wi-Fi Raw (Layer 2, Layer 3 e Layer 4) desenvolvida em C++ nativo para o ecossistema ESP-IDF. Focada em testes de estresse, análise de infraestrutura e estudos de segurança ofensiva, esta ferramenta testa o limite absoluto de equipamentos de rede, desde roteadores domésticos até hardware corporativo de provedores de internet (como roteadores de borda e ONTs).

O Silver Bullet foi otimizado exclusivamente para o hardware do M5Stack Cardputer, extraindo o máximo da arquitetura Dual-Core do ESP32-S3. Com alocação direta de memória DMA, execução na SRAM, evasão de firewalls e um Módulo de Inteligência Automática (Smart Auto-Sense), a ferramenta atua diretamente na camada física (PHY) e no Kernel do roteador alvo com perda de ciclos nula.
⚠️ Aviso Legal e Ético

Esta ferramenta foi criada estritamente para fins educacionais e testes de segurança em redes próprias ou com autorização explícita (Laboratórios de Pentest e Auditoria de Infraestrutura). A injeção de pacotes malformados e inundações de rede podem causar Kernel Panic, esgotamento de RAM e Negação de Serviço (DoS) severa em equipamentos. O uso deste software em redes de terceiros sem consentimento é ilegal e pode acarretar penalidades criminais. O autor não se responsabiliza pelo mau uso desta ferramenta.
⚙️ Funcionalidades Avançadas e Táticas Letais

Nesta versão, o código foi completamente refatorado para operar no limite físico do silício a 240MHz, incorporando as seguintes mecânicas de esgotamento de nível governamental/operadora:

    🤖 Smart Auto-Sense (Inteligência Tática): Analisa o protocolo de segurança do alvo em tempo real. Adapta os pesos de injeção dinamicamente: usa DHCP Starvation em redes abertas e prioriza TCP SYN Flood + CTS Jamming contra alvos blindados por WPA3/PMF.

    🎯 TCP SYN Sniper (Foco em Gerência): O ataque L4 agora foca 60% do tráfego forjado diretamente nas portas de serviço frágeis de CPEs: 7547 (TR-069/CWMP), 22 (SSH), 80 e 443. Isso causa picos de 100% de CPU instantâneos nas ONTs e roteadores.

    🚰 DHCP Starvation: Falsifica assinaturas (Magic Bytes) de requisições DHCP Discover via broadcast, esgotando o pool de IPs do servidor do roteador em segundos, impedindo novos clientes de conectarem.

    👻 uRPF Bypass (Evasão de Firewall): Rotaciona os IPs forjados através de sub-redes corporativas comuns (192.168.x.x, 10.x.x.x, 172.16.x.x) e redes CGNAT (100.64.x.x), garantindo que as regras Anti-Spoofing (Strict Reverse Path Forwarding) dos roteadores de borda aceitem a injeção fatal.

    🔥 L4 NAT Meltdown (Derruba 2.4GHz e 5GHz simultaneamente): Forja pacotes massivos obrigando o roteador alvo a abrir milhares de sessões NAT (Conntrack) por segundo. Como a rede 5.8GHz e as portas LAN partilham o mesmo Kernel e processador, o equipamento inteiro entra em colapso.

    📻 CTS Jamming Físico: Injeção de quadros Clear-To-Send (duration = 32767µs), enganando o protocolo CSMA/CA e forçando todos os rádios no canal a silenciarem fisicamente.

    🌡️ Thermal Throttling (Proteção Térmica): Monitoramento contínuo do sensor interno de temperatura do ESP32-S3. Se a pastilha ultrapassar os 75ºC devido ao rádio em potência máxima (20dBm), o sistema entra automaticamente em modo ECO (10dBm) para proteger o silício.

    🚀 Zero-Copy DMA & IRAM Checksum (RFC 1624): O cálculo do Checksum IP/UDP/TCP utiliza matemática diferencial incremental alocada diretamente na memória ultrarrápida (IRAM), dobrando a contagem de PPS (Pacotes Por Segundo) real.

🎮 Controles do Cardputer (Menu Tático)

O Silver Bullet permite isolamento de carga. Você pode focar todo o poder de fogo em um único gargalo do roteador pressionando as teclas em tempo real:
Tecla	Ação	Descrição
ENTER	Iniciar	Trava no alvo selecionado, analisa e inicia o ataque (Padrão: Auto).
A	Auto-Sense	Orquestrador inteligente: Combina ataques baseados na criptografia do alvo.
1	Override L2	Foco absoluto em CAM Flooding (Auth) e Deauth (Derruba clientes).
2	Override L3/L4	Foco no colapso do Roteador (NAT Meltdown + TCP Sniper + DHCP Starvation).
3	Override CTS	Foco Físico no rádio (RF Jamming CSMA/CA). Silencia o canal.
ESPAÇO	Potência	Alterna a antena entre MAX (20dBm) e ECO (10dBm) on-the-fly.
SETAS	Navegação	Move o cursor pela lista de APs no scanner.
BACKSPACE	Abortar	Interrompe a injeção imediatamente e volta ao scanner.
🏗️ Arquitetura Dual-Core e RTOS (Thread-Safe)

O sistema foi desenhado para evitar que o peso computacional extremo da injeção congele o equipamento:

    Core 0 (Motor de Injeção Letal): Dedicado exclusivamente à task_ataque. Lê as variáveis atômicas e despacha as rajadas de pacotes em blocos MALLOC_CAP_DMA sem ser interrompido por threads de UI. Conta com micro-delays precisos de 1 tick para esvaziar a fila MAC/PHY.

    Core 1 (Radar e Channel Pursuit): Abriga a telemetria, análise térmica e a interface. Se o roteador alvo acionar o Auto-Channel para fugir do ataque, o Channel Pursuit no Core 1 percebe a queda de PPS, escaneia o ambiente silenciosamente, localiza o novo canal do alvo e realinha a mira de injeção de forma automática.

🛠️ Requisitos e Instalação (Arch Linux / ESP-IDF)

    Hardware: M5Stack Cardputer (M5Stamp S3).

    Framework: ESP-IDF v5.x (via Git). Incompatível com a IDE do Arduino devido ao uso bare-metal das APIs internas de rádio da Espressif.

    Dependências: m5stack/m5unified (via IDF Component Manager).

1. Instalar Dependências do Sistema (Arch Linux)

Abra seu terminal e instale as dependências padrão para compilação cruzada:
Bash

sudo pacman -S --needed gcc git make cmake gperf python-pip python-setuptools python-wheel ninja flex bison

2. Configurar o ESP-IDF

Clone e instale o ESP-IDF da Espressif. Não esqueça de exportar o ambiente:
Bash

. $HOME/esp/esp-idf/export.sh

3. Ajustes Críticos no sdkconfig (MUITO IMPORTANTE)

Para alcançar a performance extrema e evitar gargalos na fila de hardware, você deve realizar duas alterações no menu de configuração do projeto:

Execute idf.py menuconfig e altere:

    Fila DMA: Navegue até Component config ➔ Wi-Fi ➔ Max number of dynamic TX buffers e altere de 32 para 128.

    Clock da CPU: Navegue até Component config ➔ ESP System Settings ➔ CPU frequency e altere de 160 MHz para 240 MHz.

4. Compilar e Gravar

Por fim, basta construir e "flashear" a ferramenta no seu Cardputer:
Bash

idf.py build flash monitor