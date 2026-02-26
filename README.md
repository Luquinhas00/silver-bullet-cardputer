Markdown

# 🔫 Silver Bullet

> **Ferramenta Bare-Metal de Auditoria e Estresse Wi-Fi para CPEs e Equipamentos de Telecomunicações.**

O **Silver Bullet** é um firmware de injeção de pacotes desenvolvido para o ecossistema ESP32, projetado para operar no limite do hardware. Ele contorna o agendador de tarefas padrão para entregar throughput máximo de injeção diretamente da IRAM para a interface PHY do rádio Wi-Fi. 

Ideal para testes de estresse em laboratório, homologação de CPEs, validação de regras de drop em OLTs e análise de robustez de redes sem fio.

---

## 🚀 Características Principais

* **Motor DMA & Alinhamento de Memória:** Estruturas de rede refatoradas sem *padding* para acesso direto à memória, impedindo o descarte de pacotes malformados pelo Kernel do roteador alvo.
* **DHCP Starvation Realista:** Esgotamento dinâmico de Pool IP com forja de *Magic Cookie* BOOTP e rotação de CHADDR, contornando proteções básicas de servidores `dnsmasq`.
* **TCP SYN Flood Direcionado:** Injeção L4 otimizada (RFC 1624 Checksum na IRAM) focada em portas de gerência (TR-069, SSH, HTTP, HTTPS).
* **CTS Jamming & Evasão WPA3:** Injeção de frames *Clear-to-Send* para suspensão de tráfego em redes blindadas com WPA3.
* **Recuperação Térmica Automática:** Monitoramento do silício em tempo real. Reduz a potência de transmissão (Tx Power) para o modo ECO (10dBm) ao atingir 75ºC e restaura o modo MAX (20dBm) automaticamente ao resfriar para 65ºC, evitando o travamento do chip (Thermal Throttling).
* **Reconhecimento de Estratégia Auto:** O modo inteligente escaneia a criptografia do alvo e decide o vetor mais letal (ex: WPA2 = Combo L2+L3, WPA3 = Stealth CTS+L3).
* **Channel Pursuit:** Rastreamento ativo do alvo caso a CPE tente realizar *Channel Hopping* para fugir do ataque.

---

## 🛠️ Hardware Suportado

O firmware foi projetado e otimizado para as seguintes plataformas:
* **M5Stack Cardputer** (ESP32-S3) - Suporte nativo ao teclado e display.
* **Placas de Desenvolvimento ESP32 WROOM** (Requer adaptação nos pinos de display/input se não usar interface serial).

---

## ⚙️ Pré-requisitos e Compilação

Este projeto utiliza o **ESP-IDF** nativo. Para usuários em ambientes baseados em Arch Linux, certifique-se de que as dependências do `esp-idf` estejam corretamente exportadas no seu ambiente antes da compilação.

### 1. Preparando o Ambiente
Clone o repositório e acesse a pasta do projeto:
```bash
git clone [https://github.com/luquinhas00/silver-bullet-cardputer.git](https://github.com/luquinhas00/silver-bullet-cardputer.git)
cd silver-bullet-cardputer

2. Configurações Críticas de Performance (sdkconfig.defaults)

Para garantir que o processador não crie gargalos nas funções matemáticas de Checksum, o repositório exige o arquivo sdkconfig.defaults com as seguintes flags. Não compile sem elas, ou a injeção será estrangulada em 160MHz:
Plaintext

CONFIG_PARTITION_TABLE_SINGLE_APP_LARGE=y
CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ_240=y
CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ=240
CONFIG_ESP_WIFI_DYNAMIC_TX_BUFFER_NUM=128

3. Build e Flash
Bash

idf.py build
idf.py -p /dev/ttyACM0 flash monitor

(Altere /dev/ttyACM0 para a porta correspondente do seu dispositivo).
🎮 Controles (Interface Cardputer)
Tecla	Ação
Setas UP / DOWN	Navegar pela lista de redes escaneadas.
ENTER	Selecionar o alvo e iniciar o ataque.
ESPAÇO	Alternar a potência do rádio manualmente (MAX: 20dBm / ECO: 10dBm).
A	Modo Automático: A IA interna decide o melhor vetor de ataque.
1	Modo Manual L2: Injeção bruta de Deauth/Auth.
2	Modo Manual L3/L4: TCP SYN Flood e DHCP Starvation.
3	Modo Manual CTS: Jamming limpo (Clear-to-Send).
BACKSPACE	Interromper a injeção, retornar ao scanner e limpar o alvo.