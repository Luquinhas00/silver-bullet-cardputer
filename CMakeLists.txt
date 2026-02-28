cmake_minimum_required(VERSION 3.5)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

# Esta linha diz ao compilador v4.4 para ignorar avisos irritantes e não os tratar como erros fatais
add_compile_options(-Wno-error)

project(silver_bullet)