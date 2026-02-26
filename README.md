🎯 Silver Bullet - M5 Cardputer (ESP32-S3)

Uma ferramenta avançada de injeção de pacotes Wi-Fi Raw (Layer 2 e Layer 3) desenvolvida em C++ nativo para o ecossistema ESP-IDF. Focada em testes de estresse, análise de infraestrutura e estudos de segurança ofensiva, esta ferramenta testa o limite de equipamentos de rede (desde roteadores domésticos até hardware corporativo de provedores).

O Silver Bullet foi otimizado exclusivamente para o hardware do M5Stack Cardputer, extraindo o máximo da arquitetura Dual-Core do ESP32-S3. Com alocação direta de memória e execução na SRAM, a ferramenta atua diretamente na camada física (PHY) com perda de ciclos praticamente nula.

    ⚠️ Aviso Legal e Ético

    Esta ferramenta foi criada estritamente para fins educacionais e testes de segurança em redes próprias ou com autorização explícita (Laboratórios de Pentest). A injeção de pacotes malformados (como ataques Teardrop ou anomalias de fragmentação) e inundações de rede podem causar Kernel Panic e Negação de Serviço (DoS) em roteadores e equipamentos de infraestrutura. O uso deste software em redes de terceiros sem consentimento é ilegal e pode acarretar penalidades criminais. O autor não se responsabiliza pelo mau uso desta ferramenta.

⚙️ Funcionalidades Avançadas e Otimizações de Hardware

Nesta versão, o código foi completamente refatorado para operar no limite físico do silício a 240MHz, incorporando táticas agressivas de esgotamento de recursos:

    🚀 Zero-Copy DMA: As estruturas de pacotes são alocadas diretamente na memória compatível com o módulo DMA (MALLOC_CAP_DMA), permitindo que o rádio Wi-Fi transmita os dados sem a CPU precisar copiar a memória, zerando o overhead de injeção.

    ⚡ SRAM Execution (IRAM_ATTR): Os motores criptográficos e de cálculo de Checksum rodam diretamente na RAM interna do chip, eliminando os congelamentos por Cache Miss na leitura da memória Flash SPI.

    🎲 Gerador de Entropia Xorshift32: Substituição das chamadas lentas de hardware (esp_random()) por um algoritmo bitwise ultrarrápido, gerando milhares de MACs e offsets de fragmentação instantaneamente.

    🛡️ NAV Spoofing (Jamming L2): Injeção de quadros com duration = 32767µs, forçando todos os rádios próximos a silenciarem (CSMA/CA bypass).

    💥 Auth Flood & Tabela CAM: Esgota o limite de clientes do AP enviando falsas requisições de autenticação com MACs forjados dinamicamente.

    🧠 Memory Exhaustion (L3): Disparo de pacotes IP UDP massivos com a flag More Fragments ativada e tamanhos falsificados, forçando o roteador a alocar e estourar a sua própria memória RAM global (afetando inclusive redes 5.8GHz que compartilham a mesma CPU).

    📡 Rádio Always-On: O Modem Sleep do ESP32 é nativamente desativado (WIFI_PS_NONE), forçando a antena a operar 100% do tempo em TX máximo (até 20dBm).

🏗️ Como o Código Funciona (Arquitetura Dual-Core)

O sistema foi desenhado para evitar que o peso da injeção de pacotes congele a interface ou a inteligência da ferramenta.

    Core 0 (Motor de Injeção): Dedicado exclusivamente à task_ataque. Trabalha gerando e disparando rajadas mistas de Deauth, Auth e pacotes IP fragmentados. Utiliza Smart Yielding (taskYIELD()) para sincronizar milimetricamente com o hardware, pausando a injeção apenas no microssegundo exato em que o buffer DMA do rádio precisa ser esvaziado.

    Core 1 (Radar e Interface): Abriga a task_monitoramento e a task_display. É responsável por atualizar a tela via SPI (controlado a 2 FPS para poupar barramento) e rodar o Smart Target Tracking: se o roteador alvo tentar fugir mudando de canal (Auto-Channel), o Core 1 rastreia a mudança em background e realinha a mira sem interromper o Core 0.

🛠️ Requisitos de Hardware e Software

    Hardware: M5Stack Cardputer (M5Stamp S3).

    Sistema Operacional (Dev): Arch Linux (ou derivados) recomendado.

    Framework: ESP-IDF v5.x (via Git). Nota: Não é compatível com a IDE do Arduino devido à necessidade de acesso em nível bare-metal às APIs do rádio Wi-Fi.

    Dependências: m5stack/m5unified (gerenciado automaticamente via IDF Component Manager).

🚀 Guia de Instalação e Compilação (Arch Linux)
1. Instalar Dependências do Sistema

Abra o terminal e instale os pacotes necessários para compilação cruzada do ESP32:
Bash

sudo pacman -S --needed gcc git make cmake gperf python-pip python-setuptools python-wheel ninja flex bison

2. Configurar o ESP-IDF

Siga o guia oficial da Espressif para clonar e instalar o ESP-IDF.
3. Ajuste Crítico do sdkconfig

Para que a alocação DMA funcione com a agressividade exigida por este código, você deve expandir a fila de pacotes dinâmicos do rádio.
No diretório do projeto, execute idf.py menuconfig e navegue até:
Component config ➔ Wi-Fi ➔ Max number of dynamic TX buffers.

    Altere o valor de 32 para 128.

4. Compilar e Gravar no Cardputer

Com o ambiente IDF exportado (. $HOME/esp/esp-idf/export.sh), compile e envie para o Cardputer:
Bash

idf.py build flash monitor