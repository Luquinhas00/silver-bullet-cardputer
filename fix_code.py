import re

with open('main/silver_bullet.cpp', 'r') as f:
    data = f.read()

# 1. Corrige o warning de ponteiro empacotado (Double Cast)
data = data.replace('uint16_t *data = (uint16_t *)ip;', 'uint16_t *data = (uint16_t *)(void *)ip;')

# 2. Corrige a formatação do Printf no processador do ESP32 (%lu)
data = data.replace('%u PPS', '%lu PPS')

# 3. Substitui a função de controles inteira para usar apenas o botão G0 (BtnA)
new_task = '''void task_controles(void *pvParameters) {
    while (true) {
        M5.update(); 
        if (estado_atual.load() == ESTADO_SELECIONAR) {
            if (total_alvos > 0) {
                if (M5.BtnA.wasPressed()) {
                    alvo_selecionado = (alvo_selecionado + 1) % total_alvos; 
                    desenhar_menu(); 
                }
                if (M5.BtnA.pressedFor(1000)) {
                    uint8_t ch = 1;
                    if(xSemaphoreTake(scan_mutex, portMAX_DELAY)) {
                        ch = alvos_encontrados[alvo_selecionado].primary;
                        xSemaphoreGive(scan_mutex);
                    }
                    canal_atual_alvo.store(ch); 
                    analisar_alvo_automaticamente(alvo_selecionado); 
                    modo_ativo.store(MODO_AUTOMATICO); 
                    if(xSemaphoreTake(display_mutex, portMAX_DELAY)) {
                        M5.Display.clear(); 
                        xSemaphoreGive(display_mutex);
                    }
                    flag_update_config.store(true); 
                    estado_atual.store(ESTADO_ATIRAR);
                    while(M5.BtnA.isPressed()) { M5.update(); vTaskDelay(10); }
                }
            } else if (M5.BtnA.wasPressed()) {
                escanear_redes(); desenhar_menu();
            }
        } 
        else if (estado_atual.load() == ESTADO_ATIRAR) {
            if (M5.BtnA.pressedFor(1000)) {
                alvo_perdido.store(false); 
                estado_atual.store(ESTADO_SELECIONAR); 
                escanear_redes(); 
                desenhar_menu();
                while(M5.BtnA.isPressed()) { M5.update(); vTaskDelay(10); }
            }
        }
        vTaskDelay(pdMS_TO_TICKS(50)); 
    }
}

extern "C" void app_main'''

data = re.sub(r'void task_controles\(void \*pvParameters\) \{.*?extern "C" void app_main', new_task, data, flags=re.DOTALL)

with open('main/silver_bullet.cpp', 'w') as f:
    f.write(data)
