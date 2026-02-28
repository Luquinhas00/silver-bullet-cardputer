# 🔫 Silver Bullet

**Silver Bullet** é uma ferramenta avançada de auditoria de redes sem fio e estresse de CPEs, desenvolvida especificamente para o hardware **M5Stack Cardputer (ESP32-S3)**. O projeto explora os limites físicos do rádio do ESP32 através de injeção direta de pacotes na memória (DMA), operando em *Low Level* (L2, L3 e L4) para testar a resiliência de roteadores e firewalls.

⚠️ **AVISO LEGAL:** Esta ferramenta foi criada **estritamente para testes de estresse, pesquisa de segurança e auditoria** em equipamentos de rede próprios ou com autorização explícita (Pentest). O uso desta ferramenta contra infraestruturas de terceiros sem consentimento é ilegal. O autor não se responsabiliza pelo mau uso do código.

---

## ⚙️ Arquitetura e Funcionalidades Principais

* **Motor de Injeção DMA (Direct Memory Access):** Estruturas de rede L2, L3 e L4 refatoradas sem *padding* (`__attribute__((packed))`). Os pacotes são alocados diretamente na IRAM, impedindo o descarte por anomalias e maximizando os PPS (Pacotes Por Segundo).
* **Inteligência Automática de Vetor de Ataque:** O sistema analisa o *Cipher* e a Autenticação do alvo durante o scan e decide a estratégia mais letal:
  * **Legacy (Open/WEP):** Ataque massivo L2 + L3 (TCP/UDP/DHCP).
  * **WPA2-TKIP:** Foco letal em L2.
  * **WPA2-AES:** Ataque combinado L2 + Injeção CTS.
  * **WPA3 / Blindado:** Suspensão de tráfego via CTS Jamming puro, evadindo a proteção PMF.
* **Bypass de Firewall L4 (SPI):**
  * **TCP SYN Flood:** Forja pacotes SYN com payload zero direcionados a portas de gerência conhecidas (identificadas via OUI do MAC: MikroTik, Huawei, TP-Link, ZTE, Intelbras).
  * **DHCP Starvation:** Esgotamento de pool IP forjando pacotes BOOTP com *Magic Cookie* válido e rotação de endereços de hardware.
  * **DNS Flood:** Injeção de queries DNS malformadas para sobrecarregar o daemon L7 do alvo.
* **Controle Térmico (Thermal Lock):** Monitoramento do silício em tempo real. Se o ESP32-S3 atingir **75ºC**, o firmware entra em modo ECO (reduz Tx Power) e bloqueia ações manuais. O controle e a potência máxima são restaurados automaticamente ao resfriar para **65ºC**.
* **Channel Pursuit (Rastreamento Ativo):** Se a CPE alvo realizar *Channel Hopping* para fugir da auditoria, a *Task* isolada no Core 1 congela a injeção via Mutex, rastreia o novo canal e retoma o ataque automaticamente.
* **Driver Nativo de Teclado I2C:** Suporte integrado ao chip TCA8418 do Cardputer para navegação e controle fluido pela interface.

---

## 🛠️ Hardware e Requisitos

* **Dispositivo:** M5Stack Cardputer (Processador ESP32-S3, 8MB Flash).
* **Framework Mínimo:** Espressif **ESP-IDF v4.4.x**. 
  > *Nota Arquitetural: O uso da versão 4.4 é **obrigatório**. Versões superiores (5.x) contêm drivers fechados (`libnet80211.a`) com firewalls internos que bloqueiam ativamente a injeção crua de frames de gerenciamento (ex: `0xC0` Deauth).*

---

## 🚀 Instalação e Compilação (Linux / Arch Linux)

Para extrair o potencial máximo sem as amarras das versões recentes, configure seu ambiente para a v4.4:

**1. Prepare o ESP-IDF v4.4:**
```bash
cd ~/esp/esp-idf
git fetch
git checkout release/v4.4
git submodule update --init --recursive
./install.sh esp32s3
. ./export.sh

(No Arch Linux, se o instalador reclamar do ambiente Python, instale o python-virtualenv nativamente via pacman antes de rodar o install.sh).

2. Patch do CMake (Apenas para Sistemas Bleeding Edge como Arch):
Bash

sed -i 's/cmake_minimum_required(VERSION .*)/cmake_minimum_required(VERSION 3.5)/g' ~/esp/esp-idf/components/mbedtls/mbedtls/CMakeLists.txt

3. Configure o Projeto:
Bash

cd ~/esp/silver_bullet
rm -rf build sdkconfig dependencies.lock # Limpeza de segurança
idf.py set-target esp32s3
idf.py menuconfig

Navegue até Serial flasher config -> Flash size -> Selecione 8 MB. Salve (S) e saia (Q).

4. Compile e faça o Flash:
Bash

idf.py build flash monitor

🕹️ Controles (Teclado Cardputer)

A interface responde diretamente às teclas do M5Stack Cardputer lidas via barramento I2C:

    Navegar (ID 58): Desce a seleção pela lista de APs encontrados.

    Atirar / Selecionar (ID 67): Confirma o alvo selecionado, analisa a estratégia ideal (L2/L3/CTS) e inicia a injeção.

    Parar Ataque (ID 97): Aborta a injeção DMA, libera os Mutexes e retorna ao menu de escaneamento.

    Botão Físico G0 (Backup): Permite navegar com clique simples e iniciar/parar o ataque mantendo pressionado por 1 segundo.

📊 Status do Display

Durante o ataque, a tela fornecerá telemetria em tempo real:

    SSID do Alvo: A rede em teste.

    CH & TEMP: Canal atual e Temperatura do Silício em tempo real.

    PWR: Modo de energia da antena (MAX ou ECO em caso de sobreaquecimento).

    Modo Ativo: Mostra qual vetor está sendo utilizado (ex: AUTO: WPA2-AES (L2+CTS)).

    PPS: Indicador de Packets Per Second (Pacotes Por Segundo) injetados com sucesso pelo DMA.


Você pode copiar esse bloco inteiro e salvar como `README.md` no seu repositório no GitHub. Ele cobre toda a engenharia avançada que você implementou, cita a limitação e o motivo técnico de usarmos o ESP-IDF 4.4, e mantém a postura profissional do projeto!