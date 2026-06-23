╔══════════════════════════════════════════════════════════════╗
║              DocTracker — Setup Guide                        ║
╚══════════════════════════════════════════════════════════════╝

WHAT YOU NEED TO DOWNLOAD
──────────────────────────

1. GLFW  (window + input)
   → https://www.glfw.org/download.html
   → Download: "Windows pre-compiled binaries" (64-bit)
   → You need: glfw3.h and glfw3dll.lib / libglfw3.a

2. ImGui  (the UI)
   → https://github.com/ocornut/imgui
   → Click "Code" → "Download ZIP"
   → Extract the folder and rename it to: imgui
   → Place it inside your project folder

3. SQLite3  (the database — just 2 files!)
   → https://www.sqlite.org/download.html
   → Under "Source Code" download: sqlite-amalgamation-XXXXXXX.zip
   → You only need 2 files from it:
       sqlite3.h
       sqlite3.c
   → Drop both into your project folder

4. CMake  (builds the project)
   → https://cmake.org/download/
   → Download the Windows installer (.msi)

5. A C++ Compiler
   → Option A (Windows): Visual Studio 2022 (Community — free)
     https://visualstudio.microsoft.com/
     During install, pick "Desktop development with C++"
   → Option B (Windows): MinGW-w64
     https://winlibs.com/

──────────────────────────────────────────────────────────────

YOUR PROJECT FOLDER STRUCTURE (after downloads)
─────────────────────────────────────────────────

DocTracker/
├── main.cpp          ← the code (already written)
├── CMakeLists.txt    ← build instructions (already written)
├── sqlite3.h         ← downloaded from sqlite.org
├── sqlite3.c         ← downloaded from sqlite.org
└── imgui/            ← downloaded from github
    ├── imgui.h
    ├── imgui.cpp
    ├── imgui_draw.cpp
    ├── imgui_tables.cpp
    ├── imgui_widgets.cpp
    └── backends/
        ├── imgui_impl_glfw.h
        ├── imgui_impl_glfw.cpp
        ├── imgui_impl_opengl3.h
        └── imgui_impl_opengl3.cpp

──────────────────────────────────────────────────────────────

HOW TO BUILD (step by step)
─────────────────────────────

Using Visual Studio:
  1. Open Visual Studio
  2. File → Open → CMake → select CMakeLists.txt
  3. Click the green Play button (DocTracker.exe)

Using Command Line (CMake + MinGW):
  mkdir build
  cd build
  cmake .. -G "MinGW Makefiles"
  mingw32-make
  DocTracker.exe

──────────────────────────────────────────────────────────────

HOW THE APP WORKS
──────────────────

- Open the app → enter a Project Title and Security Code
- "Create Project" = new project (first time)
- "Login"          = open existing project
- Your docs are encrypted with your Security Code
- Everything is saved in: doctracker.db  (same folder as .exe)
- If you delete doctracker.db, all data is gone

──────────────────────────────────────────────────────────────

SECURITY NOTE
──────────────
This version uses:
  - djb2 hash   for passwords  (upgrade to SHA-256 / bcrypt later)
  - XOR cipher  for content    (upgrade to AES-256 via OpenSSL later)

It is NOT production-grade encryption, but content is unreadable
without the correct Security Code.

══════════════════════════════════════════════════════════════
