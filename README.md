# 🔫 Silver Bullet

> **Ferramenta Bare-Metal de Auditoria e Estresse Wi-Fi para CPEs e Equipamentos de Telecomunicações.**

O **Silver Bullet** é um firmware de injeção de pacotes desenvolvido para o ecossistema ESP32, projetado para operar no limite do hardware. Ele contorna o agendador de tarefas padrão para entregar throughput máximo de injeção diretamente da IRAM para a interface PHY do rádio Wi-Fi. 

Ideal para testes de estresse em laboratório, homologação de CPEs, validação de regras de drop em OLTs e análise de robustez de redes sem fio.

---

## 🚀 Características Principais (Auditoria 2.0)

* **Motor DMA & Alinhamento de Memória:** Estruturas de rede refatoradas sem *padding* para acesso direto à memória, impedindo o descarte de pacotes malformados pelo Kernel do roteador alvo.
* **Inteligência L3 Realista:** Bloqueio de injeção L3 (Plaintext) em redes WPA2/WPA3. O motor foca ataques de camada de rede e transporte (TCP/UDP) exclusivamente em redes abertas ou WEP, evitando descarte silencioso no rádio (PHY/MAC) do alvo.
* **TCP SYN Flood (RFC Compliant):** Injeção L4 otimizada na IRAM focada em portas de gerência (TR-069, Winbox, HTTP/S). Os pacotes SYN são forjados com tamanho de *payload* estritamente igual a zero para burlar regras de *drop* em firewalls SPI (Stateful Packet Inspection).
* **DHCP & DNS Flood Avançado:** Esgotamento de IP com forja de *Magic Cookie* BOOTP e rotação de CHADDR. Injeção de DNS forja consultas válidas (ex: google.com) para forçar o processamento L7 e evadir filtros do `dnsmasq`.
* **CTS Jamming & Evasão:** Injeção de frames *Clear-to-Send* para suspensão de tráfego em redes blindadas com WPA3. Rotação dinâmica de *Reason Codes* L2 para burlar sistemas WIPS.
* **Controle Térmico com Thermal Lock:** Monitoramento do silício em tempo real. Reduz a Tx Power para o modo ECO (10dBm) ao atingir 75ºC. A interface trava o *override* manual do usuário durante o superaquecimento, evitando a queima do chip, e restaura o controle e a potência máxima (20dBm) ao resfriar para 65ºC.
* **Reconhecimento de Estratégia Auto:** O modo inteligente escaneia a criptografia do alvo e decide o vetor mais letal (ex: Legacy = L2+L3, WPA2-AES = L2+CTS, WPA3 = CTS Only).
* **Channel Pursuit:** Rastreamento ativo protegido por *Mutex* atômico contra *Race Conditions* de DMA, caçando a CPE caso ela tente realizar *Channel Hopping* para fugir do ataque.

---

## 🛠️ Hardware Suportado

O firmware foi projetado e otimizado para as seguintes plataformas:
* **M5Stack Cardputer** (ESP32-S3) - Suporte nativo ao teclado e display.
* **ESP32 WROOM (Placas de Desenvolvimento)** - Requer adaptação nos pinos de display/input se não usar interface serial.

---

## ⚙️ Pré-requisitos e Compilação

Este projeto utiliza o **ESP-IDF** nativo. Para usuários em ambientes baseados em Arch Linux, certifique-se de que as dependências do `esp-idf` estejam corretamente exportadas no seu ambiente antes da compilação.

### 1. Preparando o Ambiente
Clone o repositório e acesse a pasta do projeto:
```bash
git clone [https://github.com/luquinhas00/silver-bullet-cardputer.git](https://github.com/luquinhas00/silver-bullet-cardputer.git)
cd silver-bullet-cardputer

2. Configurações Críticas de Performance (sdkconfig.defaults)

Para garantir que o processador não crie gargalos nas funções matemáticas de Checksum e entregue o máximo de PPS (Pacotes Por Segundo), o repositório exige o arquivo sdkconfig.defaults com as seguintes flags. Não compile sem elas, ou a injeção será estrangulada em 160MHz.

Edite ou crie o arquivo sdkconfig.defaults na raiz do projeto:
Plaintext

CONFIG_PARTITION_TABLE_SINGLE_APP_LARGE=y
CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ_240=y
CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ=240
CONFIG_ESP_WIFI_DYNAMIC_TX_BUFFER_NUM=128
CONFIG_FREERTOS_HZ=1000

Após adicionar as linhas, limpe a configuração antiga e reconfigure:
Bash

rm sdkconfig
idf.py reconfigure

3. Build e Flash
Bash

idf.py build
idf.py -p /dev/ttyACM0 flash monitor

(Altere /dev/ttyACM0 para a porta correspondente do seu dispositivo).
🎮 Controles (Interface Cardputer)
Tecla	Ação
Setas UP / DOWN	Navegar pela lista de redes escaneadas.
ENTER	Selecionar o alvo, engatilhar a análise IA e iniciar o ataque.
ESPAÇO	Alternar a potência do rádio manualmente (MAX: 20dBm / ECO: 10dBm). Nota: Fica inoperante se o Thermal Lock estiver ativo.
A	Modo Automático: A IA interna decide o melhor vetor de ataque baseado no alvo.
1	Modo Manual L2: Injeção bruta de Deauth/Auth.
2	Modo Manual L3/L4: TCP SYN Flood, DNS e DHCP Starvation.
3	Modo Manual CTS: Jamming limpo via Clear-to-Send.
BACKSPACE	Interromper a injeção, retornar ao scanner e limpar o alvo.