idf_component_register(SRCS "silver_bullet.cpp"
                    INCLUDE_DIRS ".")
target_link_options(${COMPONENT_LIB} PUBLIC "-Wl,--allow-multiple-definition")
