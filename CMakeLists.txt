cmake_minimum_required(VERSION 3.16)
project(Clavis)

set(CMAKE_CXX_STANDARD 17)

# Windows: static link runtime so no MSVC redist needed
if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

# Find packages
find_package(OpenGL REQUIRED)
find_package(glfw3 REQUIRED)

# SQLite3 (bundled)
add_library(sqlite3 STATIC sqlite3.c)
target_compile_definitions(sqlite3 PRIVATE SQLITE_THREADSAFE=0)

# ImGui sources
set(IMGUI_DIR ${CMAKE_SOURCE_DIR}/imgui)
set(IMGUI_SOURCES
    ${IMGUI_DIR}/imgui.cpp
    ${IMGUI_DIR}/imgui_draw.cpp
    ${IMGUI_DIR}/imgui_tables.cpp
    ${IMGUI_DIR}/imgui_widgets.cpp
    ${IMGUI_DIR}/backends/imgui_impl_glfw.cpp
    ${IMGUI_DIR}/backends/imgui_impl_opengl3.cpp
)

add_executable(Clavis main.cpp ${IMGUI_SOURCES})

target_include_directories(Clavis PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${IMGUI_DIR}
    ${IMGUI_DIR}/backends
)

target_link_libraries(Clavis PRIVATE
    sqlite3
    OpenGL::GL
    glfw
)

# Windows: copy sqlite3.dll if using dynamic GLFW, or static link everything
if(WIN32)
    set_property(TARGET Clavis PROPERTY WIN32_EXECUTABLE FALSE) # console for debug
endif()