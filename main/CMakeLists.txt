idf_component_register(SRCS "silver_bullet.cpp" INCLUDE_DIRS "." REQUIRES m5unified esp_wifi nvs_flash)
target_compile_options(${COMPONENT_LIB} PRIVATE "-Wno-error=address-of-packed-member")
