#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include <GLFW/glfw3.h>
#include "sqlite3.h"
#include <string>
#include <vector>
#include <cstring>
#include <ctime>
#include <sstream>
#include <map>

#ifdef _WIN32
#include <windows.h>
#endif

// ─────────────────────────────────────────────
//  NOTE: XOR "encryption" is NOT real encryption.
//  NOTE: djb2 is NOT a secure password hash.
//        Replace with bcrypt/Argon2 before any
//        production use.
// ─────────────────────────────────────────────

std::string xorEncrypt(const std::string& data, const std::string& key) {
    std::string result = data;
    for (size_t i = 0; i < data.size(); i++)
        result[i] = data[i] ^ key[i % key.size()];
    return result;
}
std::string xorDecrypt(const std::string& data, const std::string& key) {
    return xorEncrypt(data, key);
}

std::string hashPassword(const std::string& password) {
    unsigned long hash = 5381;
    for (char c : password)
        hash = ((hash << 5) + hash) + c;
    std::ostringstream oss;
    oss << hash;
    return oss.str();
}

std::string getTimestamp() {
    time_t now = time(nullptr);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&now));
    return std::string(buf);
}

// ─────────────────────────────────────────────
//  Data structures
// ─────────────────────────────────────────────
struct Document {
    int id;
    std::string title;
    std::string content;
    std::string tag;
    std::string lastModified;
};

struct ActivityEntry {
    std::string action;
    std::string timestamp;
};

enum class Screen { LOGIN, DASHBOARD };
enum class Tab    { CATALOG, ACQUISITIONS, METRICS, LOG, GUIDE };
enum class ConfirmModal { NONE, LOGOUT, DELETE_DOC, NEW_DOC, OPEN_OTHER };

struct AppState {
    Screen screen = Screen::LOGIN;
    Tab    tab    = Tab::CATALOG;

    char projectTitle[128] = {};
    char securityCode[128] = {};
    bool authError = false;
    bool loginMode = true;

    int  currentProjectId = -1;
    std::string currentProjectTitle;

    std::vector<Document> documents;
    char searchBuf[128] = {};
    int  viewDocId      = -1;

    bool editMode  = false;
    int  editDocId = -1;
    char docTitle[256]    = {};
    char docContent[4096] = {};
    char docTag[64]       = {};

    std::vector<ActivityEntry> activity;

    int totalDocs  = 0;
    int taggedDocs = 0;
    std::string lastModified;

    ConfirmModal confirmModal    = ConfirmModal::NONE;
    int          confirmDeleteId = -1;
    std::string  confirmDeleteTitle;
};

// ─────────────────────────────────────────────
//  Theme
// ─────────────────────────────────────────────
namespace Theme {
    // Light palette
    static const ImVec4 L_WindowBg     = ImVec4(0.980f, 0.953f, 0.910f, 1.00f);
    static const ImVec4 L_ChildBg      = ImVec4(0.941f, 0.906f, 0.847f, 1.00f);
    static const ImVec4 L_FrameBg      = ImVec4(0.910f, 0.871f, 0.804f, 1.00f);
    static const ImVec4 L_FrameBgHov   = ImVec4(0.878f, 0.824f, 0.741f, 1.00f);
    static const ImVec4 L_FrameBgAct   = ImVec4(0.843f, 0.773f, 0.671f, 1.00f);
    static const ImVec4 L_TitleBg      = ImVec4(0.239f, 0.169f, 0.118f, 1.00f);
    static const ImVec4 L_Button       = ImVec4(0.545f, 0.369f, 0.235f, 1.00f);
    static const ImVec4 L_ButtonHov    = ImVec4(0.420f, 0.259f, 0.153f, 1.00f);
    static const ImVec4 L_ButtonAct    = ImVec4(0.361f, 0.208f, 0.118f, 1.00f);
    static const ImVec4 L_Header       = ImVec4(0.784f, 0.600f, 0.416f, 0.35f);
    static const ImVec4 L_HeaderHov    = ImVec4(0.545f, 0.369f, 0.235f, 0.45f);
    static const ImVec4 L_HeaderAct    = ImVec4(0.545f, 0.369f, 0.235f, 0.65f);
    static const ImVec4 L_Tab          = ImVec4(0.878f, 0.824f, 0.741f, 1.00f);
    static const ImVec4 L_TabHov       = ImVec4(0.784f, 0.600f, 0.416f, 0.80f);
    static const ImVec4 L_TabActive    = ImVec4(0.545f, 0.369f, 0.235f, 1.00f);
    static const ImVec4 L_Text         = ImVec4(0.173f, 0.102f, 0.055f, 1.00f);
    static const ImVec4 L_TextDim      = ImVec4(0.612f, 0.478f, 0.353f, 1.00f);
    static const ImVec4 L_Accent       = ImVec4(0.784f, 0.600f, 0.416f, 1.00f);
    static const ImVec4 L_AccentStrong = ImVec4(0.545f, 0.369f, 0.235f, 1.00f);
    static const ImVec4 L_Danger       = ImVec4(0.545f, 0.125f, 0.125f, 1.00f);
    static const ImVec4 L_Border       = ImVec4(0.353f, 0.216f, 0.118f, 0.22f);
    static const ImVec4 L_Scrollbar    = ImVec4(0.545f, 0.369f, 0.235f, 1.00f);
    // Active tab text: parchment on dark button (light mode)
    static const ImVec4 L_TabText      = ImVec4(0.980f, 0.953f, 0.910f, 1.00f);

    // Dark palette
    static const ImVec4 D_WindowBg     = ImVec4(0.110f, 0.063f, 0.031f, 1.00f);
    static const ImVec4 D_ChildBg      = ImVec4(0.145f, 0.086f, 0.047f, 1.00f);
    static const ImVec4 D_FrameBg      = ImVec4(0.196f, 0.122f, 0.067f, 1.00f);
    static const ImVec4 D_FrameBgHov   = ImVec4(0.247f, 0.157f, 0.090f, 1.00f);
    static const ImVec4 D_FrameBgAct   = ImVec4(0.314f, 0.204f, 0.118f, 1.00f);
    static const ImVec4 D_TitleBg      = ImVec4(0.082f, 0.047f, 0.024f, 1.00f);
    static const ImVec4 D_Button       = ImVec4(0.545f, 0.369f, 0.235f, 1.00f);
    static const ImVec4 D_ButtonHov    = ImVec4(0.627f, 0.471f, 0.314f, 1.00f);
    static const ImVec4 D_ButtonAct    = ImVec4(0.784f, 0.600f, 0.416f, 1.00f);
    static const ImVec4 D_Header       = ImVec4(0.545f, 0.369f, 0.235f, 0.35f);
    static const ImVec4 D_HeaderHov    = ImVec4(0.545f, 0.369f, 0.235f, 0.55f);
    static const ImVec4 D_HeaderAct    = ImVec4(0.627f, 0.471f, 0.314f, 0.75f);
    static const ImVec4 D_Tab          = ImVec4(0.196f, 0.122f, 0.067f, 1.00f);
    static const ImVec4 D_TabHov       = ImVec4(0.545f, 0.369f, 0.235f, 0.75f);
    static const ImVec4 D_TabActive    = ImVec4(0.545f, 0.369f, 0.235f, 1.00f);
    static const ImVec4 D_Text         = ImVec4(0.941f, 0.875f, 0.753f, 1.00f);
    static const ImVec4 D_TextDim      = ImVec4(0.545f, 0.416f, 0.294f, 1.00f);
    static const ImVec4 D_Accent       = ImVec4(0.941f, 0.776f, 0.580f, 1.00f);
    static const ImVec4 D_AccentStrong = ImVec4(0.784f, 0.600f, 0.416f, 1.00f);
    static const ImVec4 D_Danger       = ImVec4(0.753f, 0.251f, 0.251f, 1.00f);
    static const ImVec4 D_Border       = ImVec4(0.784f, 0.600f, 0.416f, 0.18f);
    static const ImVec4 D_Scrollbar    = ImVec4(0.545f, 0.369f, 0.235f, 1.00f);
    // Active tab text: warm cream on amber button (dark mode)
    static const ImVec4 D_TabText      = ImVec4(0.941f, 0.875f, 0.753f, 1.00f);

    static bool darkMode = false;

    // Accessors — always call these instead of touching palette constants directly
    static ImVec4 WindowBg()      { return darkMode ? D_WindowBg     : L_WindowBg; }
    static ImVec4 ChildBg()       { return darkMode ? D_ChildBg      : L_ChildBg; }
    static ImVec4 FrameBg()       { return darkMode ? D_FrameBg      : L_FrameBg; }
    static ImVec4 Accent()        { return darkMode ? D_Accent       : L_Accent; }
    static ImVec4 AccentStrong()  { return darkMode ? D_AccentStrong : L_AccentStrong; }
    static ImVec4 Button()        { return darkMode ? D_Button       : L_Button; }
    static ImVec4 ButtonHov()     { return darkMode ? D_ButtonHov    : L_ButtonHov; }
    static ImVec4 ButtonAct()     { return darkMode ? D_ButtonAct    : L_ButtonAct; }
    static ImVec4 Danger()        { return darkMode ? D_Danger       : L_Danger; }
    static ImVec4 TextPrimary()   { return darkMode ? D_Text         : L_Text; }
    static ImVec4 TextDim()       { return darkMode ? D_TextDim      : L_TextDim; }
    static ImVec4 TabText()       { return darkMode ? D_TabText      : L_TabText; }
}

// ─────────────────────────────────────────────
//  OS dark-mode detection
// ─────────────────────────────────────────────
static bool DetectDarkMode() {
#ifdef _WIN32
    DWORD val = 1, sz = sizeof(val);
    RegGetValueA(HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
        "AppsUseLightTheme", RRF_RT_REG_DWORD, nullptr, &val, &sz);
    return val == 0;
#else
    const char* env = getenv("GTK_THEME");
    if (env && strstr(env, "dark")) return true;
    return false;
#endif
}

// ─────────────────────────────────────────────
//  Apply library theme
// ─────────────────────────────────────────────
static void ApplyLibraryTheme() {
    Theme::darkMode = DetectDarkMode();

    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowRounding    = 6.0f;
    style.ChildRounding     = 6.0f;
    style.FrameRounding     = 5.0f;
    style.PopupRounding     = 6.0f;
    style.ScrollbarRounding = 4.0f;
    style.GrabRounding      = 4.0f;
    style.TabRounding       = 5.0f;
    style.WindowPadding     = ImVec2(14.0f, 12.0f);
    style.FramePadding      = ImVec2(10.0f,  6.0f);
    style.ItemSpacing       = ImVec2(10.0f,  8.0f);
    style.ItemInnerSpacing  = ImVec2( 6.0f,  6.0f);
    style.ScrollbarSize     = 10.0f;
    style.GrabMinSize       = 10.0f;
    style.IndentSpacing     = 18.0f;
    style.WindowBorderSize  = 1.0f;
    style.ChildBorderSize   = 1.0f;
    style.PopupBorderSize   = 1.0f;
    style.FrameBorderSize   = 0.5f;
    style.TabBorderSize     = 0.5f;

    bool dk = Theme::darkMode;
    ImVec4* c = style.Colors;

    c[ImGuiCol_WindowBg]             = dk ? Theme::D_WindowBg    : Theme::L_WindowBg;
    c[ImGuiCol_ChildBg]              = dk ? Theme::D_ChildBg     : Theme::L_ChildBg;
    c[ImGuiCol_PopupBg]              = dk ? ImVec4(0.133f,0.078f,0.039f,1.f) : ImVec4(0.975f,0.945f,0.898f,1.f);
    c[ImGuiCol_MenuBarBg]            = dk ? ImVec4(0.161f,0.098f,0.055f,1.f) : ImVec4(0.929f,0.890f,0.820f,1.f);
    c[ImGuiCol_Border]               = dk ? Theme::D_Border      : Theme::L_Border;
    c[ImGuiCol_BorderShadow]         = ImVec4(0,0,0,0);
    c[ImGuiCol_FrameBg]              = dk ? Theme::D_FrameBg     : Theme::L_FrameBg;
    c[ImGuiCol_FrameBgHovered]       = dk ? Theme::D_FrameBgHov  : Theme::L_FrameBgHov;
    c[ImGuiCol_FrameBgActive]        = dk ? Theme::D_FrameBgAct  : Theme::L_FrameBgAct;
    c[ImGuiCol_TitleBg]              = dk ? Theme::D_TitleBg     : Theme::L_TitleBg;
    c[ImGuiCol_TitleBgActive]        = dk ? Theme::D_TitleBg     : Theme::L_TitleBg;
    c[ImGuiCol_TitleBgCollapsed]     = dk ? ImVec4(0.082f,0.047f,0.024f,0.75f) : ImVec4(0.239f,0.169f,0.118f,0.75f);
    c[ImGuiCol_ScrollbarBg]          = dk ? Theme::D_ChildBg     : Theme::L_ChildBg;
    c[ImGuiCol_ScrollbarGrab]        = dk ? Theme::D_Scrollbar   : Theme::L_Scrollbar;
    c[ImGuiCol_ScrollbarGrabHovered] = dk ? Theme::D_ButtonHov   : Theme::L_ButtonHov;
    c[ImGuiCol_ScrollbarGrabActive]  = dk ? Theme::D_ButtonAct   : Theme::L_ButtonAct;
    c[ImGuiCol_CheckMark]            = dk ? Theme::D_AccentStrong: Theme::L_AccentStrong;
    c[ImGuiCol_SliderGrab]           = dk ? Theme::D_AccentStrong: Theme::L_AccentStrong;
    c[ImGuiCol_SliderGrabActive]     = dk ? Theme::D_Accent      : Theme::L_Accent;
    c[ImGuiCol_Button]               = dk ? Theme::D_Button      : Theme::L_Button;
    c[ImGuiCol_ButtonHovered]        = dk ? Theme::D_ButtonHov   : Theme::L_ButtonHov;
    c[ImGuiCol_ButtonActive]         = dk ? Theme::D_ButtonAct   : Theme::L_ButtonAct;
    c[ImGuiCol_Header]               = dk ? Theme::D_Header      : Theme::L_Header;
    c[ImGuiCol_HeaderHovered]        = dk ? Theme::D_HeaderHov   : Theme::L_HeaderHov;
    c[ImGuiCol_HeaderActive]         = dk ? Theme::D_HeaderAct   : Theme::L_HeaderAct;
    c[ImGuiCol_Separator]            = dk ? ImVec4(0.784f,0.600f,0.416f,0.20f) : ImVec4(0.353f,0.216f,0.118f,0.25f);
    c[ImGuiCol_SeparatorHovered]     = dk ? ImVec4(0.784f,0.600f,0.416f,0.50f) : ImVec4(0.545f,0.369f,0.235f,0.55f);
    c[ImGuiCol_SeparatorActive]      = dk ? ImVec4(0.784f,0.600f,0.416f,0.80f) : ImVec4(0.545f,0.369f,0.235f,0.85f);
    c[ImGuiCol_ResizeGrip]           = dk ? ImVec4(0.784f,0.600f,0.416f,0.18f) : ImVec4(0.545f,0.369f,0.235f,0.20f);
    c[ImGuiCol_ResizeGripHovered]    = dk ? ImVec4(0.784f,0.600f,0.416f,0.50f) : ImVec4(0.545f,0.369f,0.235f,0.55f);
    c[ImGuiCol_ResizeGripActive]     = dk ? ImVec4(0.941f,0.776f,0.580f,0.80f) : ImVec4(0.545f,0.369f,0.235f,0.85f);
    c[ImGuiCol_Tab]                  = dk ? Theme::D_Tab         : Theme::L_Tab;
    c[ImGuiCol_TabHovered]           = dk ? Theme::D_TabHov      : Theme::L_TabHov;
    c[ImGuiCol_TabActive]            = dk ? Theme::D_TabActive   : Theme::L_TabActive;
    c[ImGuiCol_TabUnfocused]         = dk ? ImVec4(0.145f,0.086f,0.047f,1.f) : ImVec4(0.910f,0.871f,0.804f,1.f);
    c[ImGuiCol_TabUnfocusedActive]   = dk ? ImVec4(0.314f,0.204f,0.118f,1.f) : ImVec4(0.784f,0.600f,0.416f,0.65f);
    c[ImGuiCol_Text]                 = dk ? Theme::D_Text        : Theme::L_Text;
    c[ImGuiCol_TextDisabled]         = dk ? Theme::D_TextDim     : Theme::L_TextDim;
    c[ImGuiCol_PlotLines]            = dk ? Theme::D_AccentStrong: Theme::L_AccentStrong;
    c[ImGuiCol_PlotLinesHovered]     = dk ? Theme::D_Accent      : Theme::L_Accent;
    c[ImGuiCol_PlotHistogram]        = dk ? Theme::D_AccentStrong: Theme::L_AccentStrong;
    c[ImGuiCol_PlotHistogramHovered] = dk ? Theme::D_Accent      : Theme::L_Accent;
    c[ImGuiCol_TableHeaderBg]        = dk ? Theme::D_FrameBg     : Theme::L_FrameBgHov;
    c[ImGuiCol_TableBorderStrong]    = dk ? ImVec4(0.784f,0.600f,0.416f,0.30f) : ImVec4(0.353f,0.216f,0.118f,0.35f);
    c[ImGuiCol_TableBorderLight]     = dk ? ImVec4(0.784f,0.600f,0.416f,0.15f) : ImVec4(0.353f,0.216f,0.118f,0.18f);
    c[ImGuiCol_TableRowBg]           = ImVec4(0,0,0,0);
    c[ImGuiCol_TableRowBgAlt]        = dk ? ImVec4(0.784f,0.600f,0.416f,0.06f) : ImVec4(0.353f,0.216f,0.118f,0.05f);
    c[ImGuiCol_TextSelectedBg]       = dk ? ImVec4(0.545f,0.369f,0.235f,0.45f) : ImVec4(0.784f,0.600f,0.416f,0.40f);
    c[ImGuiCol_DragDropTarget]       = ImVec4(0.784f,0.600f,0.416f,0.90f);
    c[ImGuiCol_NavHighlight]         = dk ? Theme::D_AccentStrong: Theme::L_AccentStrong;
    c[ImGuiCol_ModalWindowDimBg]     = dk ? ImVec4(0.063f,0.031f,0.008f,0.55f) : ImVec4(0.173f,0.102f,0.055f,0.40f);
}

// ─────────────────────────────────────────────
//  Database helpers
// ─────────────────────────────────────────────
sqlite3* db = nullptr;

void initDB() {
    sqlite3_open("doctracker.db", &db);
    sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS projects ("
        "  id       INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  title    TEXT UNIQUE NOT NULL,"
        "  password TEXT NOT NULL,"
        "  created  TEXT NOT NULL"
        ");", nullptr, nullptr, nullptr);
    sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS documents ("
        "  id            INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  project_id    INTEGER NOT NULL,"
        "  title         TEXT NOT NULL,"
        "  content       TEXT NOT NULL,"
        "  tag           TEXT,"
        "  last_modified TEXT NOT NULL,"
        "  FOREIGN KEY(project_id) REFERENCES projects(id)"
        ");", nullptr, nullptr, nullptr);
    sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS activity ("
        "  id         INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  project_id INTEGER NOT NULL,"
        "  action     TEXT NOT NULL,"
        "  timestamp  TEXT NOT NULL"
        ");", nullptr, nullptr, nullptr);
}

void logActivity(int projectId, const std::string& action) {
    std::string ts = getTimestamp();
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db,
        "INSERT INTO activity (project_id,action,timestamp) VALUES (?1,?2,?3);",
        -1, &stmt, nullptr);
    sqlite3_bind_int (stmt, 1, projectId);
    sqlite3_bind_text(stmt, 2, action.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, ts.c_str(),     -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

int loginProject(const std::string& title, const std::string& code) {
    std::string hashed = hashPassword(code);
    int foundId = -1;
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db,
        "SELECT id FROM projects WHERE title=?1 AND password=?2;",
        -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, title.c_str(),  -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, hashed.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt) == SQLITE_ROW) foundId = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return foundId;
}

int signupProject(const std::string& title, const std::string& code) {
    std::string hashed = hashPassword(code);
    std::string ts     = getTimestamp();
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db,
        "INSERT OR IGNORE INTO projects (title,password,created) VALUES (?1,?2,?3);",
        -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, title.c_str(),  -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, hashed.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, ts.c_str(),     -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return loginProject(title, code);
}

void loadDocuments(AppState& state) {
    state.documents.clear();
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db,
        "SELECT id,title,content,tag,last_modified FROM documents "
        "WHERE project_id=?1 ORDER BY last_modified DESC;",
        -1, &stmt, nullptr);
    sqlite3_bind_int(stmt, 1, state.currentProjectId);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Document d;
        d.id           = sqlite3_column_int(stmt, 0);
        d.title        = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        d.content      = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        d.tag          = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        d.lastModified = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        state.documents.push_back(d);
    }
    sqlite3_finalize(stmt);
}

void loadActivity(AppState& state) {
    state.activity.clear();
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db,
        "SELECT action,timestamp FROM activity "
        "WHERE project_id=?1 ORDER BY id DESC LIMIT 50;",
        -1, &stmt, nullptr);
    sqlite3_bind_int(stmt, 1, state.currentProjectId);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        ActivityEntry a;
        a.action    = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        a.timestamp = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        state.activity.push_back(a);
    }
    sqlite3_finalize(stmt);
}

void computeStats(AppState& state) {
    state.totalDocs    = (int)state.documents.size();
    state.taggedDocs   = 0;
    state.lastModified = "";
    for (auto& d : state.documents) {
        if (!d.tag.empty()) state.taggedDocs++;
        if (state.lastModified.empty()) state.lastModified = d.lastModified;
    }
}

void saveDocument(AppState& state) {
    std::string title   = state.docTitle;
    std::string content = state.docContent;
    std::string tag     = state.docTag;
    std::string ts      = getTimestamp();
    sqlite3_stmt* stmt  = nullptr;
    if (state.editMode && state.editDocId >= 0) {
        sqlite3_prepare_v2(db,
            "UPDATE documents SET title=?1,content=?2,tag=?3,last_modified=?4 WHERE id=?5;",
            -1, &stmt, nullptr);
        sqlite3_bind_text(stmt, 1, title.c_str(),   -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, content.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, tag.c_str(),     -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, ts.c_str(),      -1, SQLITE_TRANSIENT);
        sqlite3_bind_int (stmt, 5, state.editDocId);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        logActivity(state.currentProjectId, "Edited record: " + title);
    } else {
        sqlite3_prepare_v2(db,
            "INSERT INTO documents (project_id,title,content,tag,last_modified) "
            "VALUES (?1,?2,?3,?4,?5);",
            -1, &stmt, nullptr);
        sqlite3_bind_int (stmt, 1, state.currentProjectId);
        sqlite3_bind_text(stmt, 2, title.c_str(),   -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, content.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, tag.c_str(),     -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 5, ts.c_str(),      -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        logActivity(state.currentProjectId, "Added record: " + title);
    }
    loadDocuments(state);
    computeStats(state);
}

void deleteDocument(AppState& state, int docId, const std::string& docTitle) {
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db, "DELETE FROM documents WHERE id=?1;", -1, &stmt, nullptr);
    sqlite3_bind_int(stmt, 1, docId);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    logActivity(state.currentProjectId, "Deleted record: " + docTitle);
    loadDocuments(state);
    computeStats(state);
}

void clearAddEdit(AppState& state) {
    state.editMode  = false;
    state.editDocId = -1;
    memset(state.docTitle,   0, sizeof(state.docTitle));
    memset(state.docContent, 0, sizeof(state.docContent));
    memset(state.docTag,     0, sizeof(state.docTag));
}

// FIX: also clears edit state and search so nothing leaks on re-login
static void clearSession(AppState& state) {
    state.currentProjectId = -1;
    state.currentProjectTitle.clear();
    memset(state.securityCode, 0, sizeof(state.securityCode));
    memset(state.projectTitle, 0, sizeof(state.projectTitle));
    memset(state.searchBuf,    0, sizeof(state.searchBuf));
    state.documents.clear();
    state.activity.clear();
    state.authError    = false;
    state.confirmModal = ConfirmModal::NONE;
    state.viewDocId    = -1;
    // FIX: reset edit state so it doesn't bleed into the next session
    clearAddEdit(state);
}

// ─────────────────────────────────────────────
//  UI helpers
// ─────────────────────────────────────────────

// FIX: removed the misleading `colored` bool — two clear functions instead
static void CenteredTextColored(const char* text, ImVec4 color) {
    float w = ImGui::GetWindowSize().x;
    float t = ImGui::CalcTextSize(text).x;
    ImGui::SetCursorPosX((w - t) * 0.5f);
    ImGui::TextColored(color, "%s", text);
}
static void CenteredTextDimmed(const char* text) {
    float w = ImGui::GetWindowSize().x;
    float t = ImGui::CalcTextSize(text).x;
    ImGui::SetCursorPosX((w - t) * 0.5f);
    ImGui::TextDisabled("%s", text);
}

// FIX: PushDangerButton uses Theme::Danger() consistently — no inline ternaries
static void PushDangerButton() {
    ImGui::PushStyleColor(ImGuiCol_Button,
        Theme::Danger());
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered,
        Theme::darkMode ? ImVec4(0.850f,0.300f,0.300f,1.f)
                        : ImVec4(0.420f,0.090f,0.090f,1.f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive,
        Theme::darkMode ? ImVec4(0.950f,0.350f,0.350f,1.f)
                        : ImVec4(0.320f,0.060f,0.060f,1.f));
}

// FIX: active tab text now uses Theme::TabText() so it's correct in both modes
static void PushActiveTabButton() {
    ImGui::PushStyleColor(ImGuiCol_Button,        Theme::AccentStrong());
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, Theme::ButtonHov());
    ImGui::PushStyleColor(ImGuiCol_ButtonActive,  Theme::ButtonAct());
    ImGui::PushStyleColor(ImGuiCol_Text,          Theme::TabText());
}

// ─────────────────────────────────────────────
//  Confirm modal
// ─────────────────────────────────────────────
static bool renderConfirmModal(const char* popupId, const char* title,
                               const char* message,
                               const char* confirmLabel = "Confirm",
                               bool dangerBtn = true)
{
    bool confirmed = false;
    ImGui::SetNextWindowSize(ImVec2(560, 300), ImGuiCond_Always);
    ImGui::SetNextWindowPos(
        ImVec2(ImGui::GetIO().DisplaySize.x * 0.5f,
               ImGui::GetIO().DisplaySize.y * 0.5f),
        ImGuiCond_Always, ImVec2(0.5f, 0.5f));

    if (ImGui::BeginPopupModal(popupId, nullptr,
            ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize))
    {
        ImGui::Spacing();
        ImGui::SetWindowFontScale(1.25f);
        // FIX: use Theme::Danger() and Theme::Accent() — no inline raw ternaries
        ImVec4 titleColor = dangerBtn ? Theme::Danger() : Theme::Accent();
        CenteredTextColored(title, titleColor);
        ImGui::SetWindowFontScale(1.0f);
        ImGui::Separator();
        ImGui::Spacing();

        float msgW = ImGui::CalcTextSize(message).x;
        ImGui::SetCursorPosX((560.0f - msgW) * 0.5f);
        ImGui::TextUnformatted(message);
        ImGui::Spacing();
        ImGui::Separator();

        float btnW = 170.0f;
        ImGui::SetCursorPosX((560.0f - btnW * 2 - 18.0f) * 0.5f);
        if (ImGui::Button("Cancel", ImVec2(btnW, 42)))
            ImGui::CloseCurrentPopup();
        ImGui::SameLine(0, 18);
        if (dangerBtn) PushDangerButton();
        if (ImGui::Button(confirmLabel, ImVec2(btnW, 42))) {
            confirmed = true;
            ImGui::CloseCurrentPopup();
        }
        if (dangerBtn) ImGui::PopStyleColor(3);
        ImGui::EndPopup();
    }
    return confirmed;
}

// ─────────────────────────────────────────────
//  LOGIN SCREEN
// ─────────────────────────────────────────────
void renderLogin(AppState& state) {
    ImGuiIO& io = ImGui::GetIO();
    ImGui::SetNextWindowSize(io.DisplaySize, ImGuiCond_Always);
    ImGui::SetNextWindowPos(ImVec2(0, 0), ImGuiCond_Always);
    ImGui::Begin("##login", nullptr,
        ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove);

    float cardW = 650.0f, cardH = 580.0f;
    ImGui::SetCursorPos(ImVec2(
        (io.DisplaySize.x - cardW) * 0.5f,
        (io.DisplaySize.y - cardH) * 0.5f));

    ImGui::BeginChild("##logincard", ImVec2(cardW, cardH), true);

    ImGui::Spacing();
    ImGui::SetWindowFontScale(1.5f);
    CenteredTextColored("DocTracker", Theme::AccentStrong());
    ImGui::SetWindowFontScale(1.0f);
    ImGui::Spacing();
    CenteredTextDimmed("Your cozy reading room archive");
    ImGui::Spacing(); ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing(); ImGui::Spacing();

    // Login / Register toggle
    {
        ImGui::SetCursorPosX((cardW - 180.0f) * 0.5f);
        
        bool loginPushed = false;
        if (state.loginMode) { PushActiveTabButton(); loginPushed = true; }
        if (ImGui::Button("Login", ImVec2(86, 32))) state.loginMode = true;
        if (loginPushed) ImGui::PopStyleColor(4);
        
        ImGui::SameLine(0, 8);
        
        bool registerPushed = false;
        if (!state.loginMode) { PushActiveTabButton(); registerPushed = true; }
        if (ImGui::Button("Register", ImVec2(0, 0))) state.loginMode = false;
        if (registerPushed) ImGui::PopStyleColor(4);
    }
    

    ImGui::Spacing(); ImGui::Spacing();

    // FIX: labels above each field instead of SameLine after full-width widget
    float fieldW = cardW - 60.0f;

    ImGui::SetCursorPosX(30.0f);
    ImGui::TextDisabled("Archive name");
    ImGui::SetCursorPosX(30.0f);
    ImGui::SetNextItemWidth(fieldW);
    ImGui::InputText("##archivetitle", state.projectTitle, sizeof(state.projectTitle));

    ImGui::Spacing();
    ImGui::SetCursorPosX(30.0f);
    ImGui::TextDisabled("Security code");
    ImGui::SetCursorPosX(30.0f);
    ImGui::SetNextItemWidth(fieldW);
    ImGui::InputText("##seccode", state.securityCode, sizeof(state.securityCode),
                     ImGuiInputTextFlags_Password);

    ImGui::Spacing();
    if (state.authError) {
        ImGui::SetCursorPosX(30.0f);
        ImGui::TextColored(Theme::Danger(), "%s",
            state.loginMode
                ? "Archive not found or incorrect code."
                : "That archive name is already taken.");
    }

    ImGui::Spacing(); ImGui::Spacing();
    ImGui::SetCursorPosX(30.0f);
    if (ImGui::Button(state.loginMode ? "Open archive" : "Create archive",
                      ImVec2(fieldW, 38)))
    {
        std::string title = state.projectTitle;
        std::string code  = state.securityCode;
        if (!title.empty() && !code.empty()) {
            int id = state.loginMode
                ? loginProject(title, code)
                : signupProject(title, code);
            if (id >= 0) {
                state.currentProjectId    = id;
                state.currentProjectTitle = title;
                state.authError           = false;
                state.screen              = Screen::DASHBOARD;
                loadDocuments(state);
                loadActivity(state);
                computeStats(state);
                logActivity(id, state.loginMode ? "Logged in" : "Registered archive");
            } else {
                state.authError = true;
            }
        }
    }
    ImGui::Spacing(); ImGui::Spacing();
    ImGui::Separator();
    ImGui::SetWindowFontScale(0.85f);
    CenteredTextDimmed("v1.0.0");
    ImGui::SetCursorPosX((cardW - 350.0f) * 0.5f);
    ImGui::Text("Let you documentaries and reading \n   notes in a cozy archive.");
    
    if (ImGui::Button("Help", ImVec2(86, 32))) {
        ImGui::OpenPopup("##help");
    }
    // Help popup
        ImGui::SetNextWindowSize(ImVec2(480, 320), ImGuiCond_Always);
        ImGui::SetNextWindowPos(
            ImVec2(ImGui::GetIO().DisplaySize.x * 0.5f,
                ImGui::GetIO().DisplaySize.y * 0.5f),
            ImGuiCond_Always, ImVec2(0.5f, 0.5f));
        if (ImGui::BeginPopupModal("##help", nullptr,
                ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize))
        {
            ImGui::Spacing();
            ImGui::SetWindowFontScale(1.25f);
            CenteredTextColored("Help", Theme::AccentStrong());
            ImGui::SetWindowFontScale(1.0f);
            ImGui::Separator();
            ImGui::Spacing();

            ImGui::TextWrapped(
                "DocTracker is a cozy archive for your reading notes and documents.\n\n"
                "[] Enter an archive name and security code to create or open an archive.\n\n"
                "[] Each archive is separate — your documents stay organized.\n\n"
                "[] Use the Catalog tab to add, edit, and search your records.\n\n"
                "[] Tags help you categorize and find records quickly.\n\n\n"
            "Your archive is yours alone. Only those you trust enough to share "
            "your archive name and security code with may enter. There are no "
            "spare keys hidden under the mat."
            );
            ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
            if (ImGui::Button("Close", ImVec2(120, 32)))
                ImGui::CloseCurrentPopup();
            ImGui::EndPopup();
        }
    
    ImGui::EndChild();
    ImGui::End();
}

// ─────────────────────────────────────────────
//  DASHBOARD – tab content
// ─────────────────────────────────────────────
static void renderCatalog(AppState& state) {
    // Search + add row
    ImGui::SetNextItemWidth(280.0f);
    ImGui::InputText("##search", state.searchBuf, sizeof(state.searchBuf));
    ImGui::SameLine(0, 8);
    ImGui::TextDisabled("Search");
    ImGui::SameLine(0, 20);
    if (ImGui::Button("+ Add record", ImVec2(0, 0))) {
        clearAddEdit(state);
        state.editMode  = true;
        state.editDocId = -1;
    }

    ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();

    // Inline add/edit form
    if (state.editMode) {
        ImGui::PushStyleColor(ImGuiCol_ChildBg, Theme::FrameBg());
        ImGui::BeginChild("##editform", ImVec2(0, 0), true);

        ImGui::TextColored(Theme::AccentStrong(),
            state.editDocId >= 0 ? "Edit record" : "New record");
        ImGui::Spacing();

        // FIX: labels above each field
        ImGui::TextDisabled("Title");
        ImGui::SetNextItemWidth(-1);
        ImGui::InputText("##doctitle", state.docTitle, sizeof(state.docTitle));

        ImGui::Spacing();
        ImGui::TextDisabled("Content");
        ImGui::SetNextItemWidth(-1);
        ImGui::InputTextMultiline("##doccontent", state.docContent,
                                  sizeof(state.docContent), ImVec2(-1, 80));

        ImGui::Spacing();
        ImGui::TextDisabled("Tag (optional)");
        ImGui::SetNextItemWidth(220);
        ImGui::InputText("##doctag", state.docTag, sizeof(state.docTag));

        ImGui::Spacing();
        if (ImGui::Button("Save", ImVec2(110, 32))) {
            if (strlen(state.docTitle) > 0) {
                saveDocument(state);
                clearAddEdit(state);
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(110, 32))) clearAddEdit(state);

        ImGui::EndChild();
        ImGui::PopStyleColor();
        ImGui::Spacing();
    }

    // Document list
    std::string search = state.searchBuf;
    // FIX: track which doc to delete outside the loop so OpenPopup fires correctly
    int pendingDeleteId = -1;
    std::string pendingDeleteTitle;

    for (auto& doc : state.documents) {
        if (!search.empty()) {
            std::string t = doc.title, s = search;
            for (auto& ch : t) ch = (char)tolower(ch);
            for (auto& ch : s) ch = (char)tolower(ch);
            if (t.find(s) == std::string::npos) continue;
        }

        ImGui::PushID(doc.id);
        ImGui::PushStyleColor(ImGuiCol_ChildBg, Theme::ChildBg());
        ImGui::BeginChild("##docrow", ImVec2(-1, 100), true);

        ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 4);
        ImGui::TextColored(Theme::Accent(), "[ ]");
        ImGui::SameLine();
        ImGui::Text("%s", doc.title.c_str());
        if (!doc.tag.empty()) {
            ImGui::SameLine();
            ImGui::PushStyleColor(ImGuiCol_Text, Theme::AccentStrong());
            ImGui::Text("[%s]", doc.tag.c_str());
            ImGui::PopStyleColor();
        }

        ImGui::TextDisabled("  Modified: %s", doc.lastModified.c_str());

        float btnStartX = ImGui::GetWindowWidth() - 230.0f;
        ImGui::SameLine(btnStartX);
        if (ImGui::SmallButton("View")) state.viewDocId = doc.id;
        ImGui::SameLine();
        if (ImGui::SmallButton("Edit")) {
            state.editMode  = true;
            state.editDocId = doc.id;
            strncpy(state.docTitle,   doc.title.c_str(),   sizeof(state.docTitle)   - 1);
            strncpy(state.docContent, doc.content.c_str(), sizeof(state.docContent) - 1);
            strncpy(state.docTag,     doc.tag.c_str(),     sizeof(state.docTag)     - 1);
        }
        ImGui::SameLine();
        PushDangerButton();
        if (ImGui::SmallButton("Delete")) {
            pendingDeleteId    = doc.id;
            pendingDeleteTitle = doc.title;
        }
        ImGui::PopStyleColor(3);

        ImGui::EndChild();
        ImGui::PopStyleColor();
        ImGui::PopID();
        ImGui::Spacing();
    }

    // FIX: OpenPopup called outside the per-doc loop, same ID stack level as BeginPopupModal
    if (pendingDeleteId >= 0) {
        state.confirmModal       = ConfirmModal::DELETE_DOC;
        state.confirmDeleteId    = pendingDeleteId;
        state.confirmDeleteTitle = pendingDeleteTitle;
        ImGui::OpenPopup("##confirmdel");
    }
    if (renderConfirmModal("##confirmdel", "Delete record",
            ("Delete \"" + state.confirmDeleteTitle + "\"? This cannot be undone.").c_str(),
            "Delete", true))
    {
        deleteDocument(state, state.confirmDeleteId, state.confirmDeleteTitle);
        state.confirmModal = ConfirmModal::NONE;
    }

    // FIX: view doc is a proper modal popup, not a floating Begin() window
    if (state.viewDocId >= 0)
        ImGui::OpenPopup("##viewdoc");

    ImGui::SetNextWindowSize(ImVec2(600, 420), ImGuiCond_Always);
    ImGui::SetNextWindowPos(
        ImVec2(ImGui::GetIO().DisplaySize.x * 0.5f,
               ImGui::GetIO().DisplaySize.y * 0.5f),
        ImGuiCond_Always, ImVec2(0.5f, 0.5f));
    if (ImGui::BeginPopupModal("##viewdoc", nullptr,
            ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize))
    {
        for (auto& d : state.documents) {
            if (d.id != state.viewDocId) continue;
            ImGui::TextColored(Theme::AccentStrong(), "%s", d.title.c_str());
            if (!d.tag.empty()) {
                ImGui::SameLine();
                ImGui::TextDisabled("[%s]", d.tag.c_str());
            }
            ImGui::TextDisabled("Last modified: %s", d.lastModified.c_str());
            ImGui::Separator(); ImGui::Spacing();
            ImGui::TextWrapped("%s", d.content.c_str());
            break;
        }
        ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
        if (ImGui::Button("Close", ImVec2(120, 32))) {
            state.viewDocId = -1;
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }
    // Guard: if popup was closed externally (e.g. Escape), reset viewDocId
    if (!ImGui::IsPopupOpen("##viewdoc") && state.viewDocId >= 0)
        state.viewDocId = -1;
}

static void renderAcquisitions(AppState& /*state*/) {
    ImGui::TextColored(Theme::AccentStrong(), "Acquisitions");
    ImGui::Spacing();
    ImGui::TextDisabled("Track incoming materials and new additions to the archive.");
    ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
    ImGui::TextDisabled("No pending acquisitions.");
}

static void renderMetrics(AppState& state) {
    ImGui::TextColored(Theme::AccentStrong(), "Archive metrics");
    ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();

    // FIX: stat cards use Theme::FrameBg() instead of hardcoded ImVec4
    auto statCard = [&](const char* label, const char* value) {
        ImGui::PushStyleColor(ImGuiCol_ChildBg, Theme::FrameBg());
        ImGui::BeginChild(label, ImVec2(0, 0), true);
        ImGui::TextDisabled("%s", label);
        ImGui::Spacing();
        ImGui::SetWindowFontScale(1.4f);
        ImGui::TextColored(Theme::AccentStrong(), "%s", value);
        ImGui::SetWindowFontScale(1.0f);
        ImGui::EndChild();
        ImGui::PopStyleColor();
    };

    statCard("Total records", std::to_string(state.totalDocs).c_str());
    ImGui::SameLine(0, 12);
    statCard("Tagged",        std::to_string(state.taggedDocs).c_str());
    ImGui::SameLine(0, 12);
    statCard("Untagged",      std::to_string(state.totalDocs - state.taggedDocs).c_str());

    ImGui::Spacing(); ImGui::Spacing();
    ImGui::TextDisabled("Last modified:  %s",
        state.lastModified.empty() ? "—" : state.lastModified.c_str());

    if (!state.documents.empty()) {
        ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
        ImGui::TextColored(Theme::Accent(), "Records by tag");
        ImGui::Spacing();
        std::map<std::string, int> tagCounts;
        for (auto& d : state.documents)
            tagCounts[d.tag.empty() ? "(untagged)" : d.tag]++;
        for (auto& [tag, count] : tagCounts) {
            ImGui::TextDisabled("%-20s", tag.c_str());
            ImGui::SameLine();
            ImGui::Text("%d", count);
        }
    }
}

static void renderLog(AppState& state) {
    ImGui::TextColored(Theme::AccentStrong(), "Activity log");
    ImGui::Spacing();
    if (ImGui::Button("Refresh", ImVec2(100, 0))) loadActivity(state);
    ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();

    if (state.activity.empty()) {
        ImGui::TextDisabled("No activity recorded yet.");
        return;
    }
    for (auto& a : state.activity) {
        ImGui::TextColored(Theme::Accent(), "[%s]", a.timestamp.c_str());
        ImGui::SameLine();
        ImGui::Text("%s", a.action.c_str());
    }
}

static void renderGuide(AppState& /*state*/) {
    ImGui::TextColored(Theme::AccentStrong(), "How to use DocTracker");
    ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();

    auto section = [&](const char* title, const char* body) {
        ImGui::TextColored(Theme::Accent(), "%s", title);
        ImGui::Spacing();
        ImGui::TextWrapped("%s", body);
        ImGui::Spacing(); ImGui::Spacing();
    };

    section("Catalog",
        "Browse, search, add, edit, and delete records in your archive. "
        "Use the search bar to filter by title. Tags help you organise records by category.");
    section("Acquisitions",
        "Track new materials being added to the archive before they are catalogued.");
    section("Metrics",
        "See a summary of your archive: total records, tagged vs untagged counts, "
        "and a breakdown of records by tag.");
    section("Activity log",
        "A timestamped log of every action taken in this archive, "
        "including logins, additions, edits, and deletions.");
    section("Archives",
        "Each archive is a separate workspace protected by its own security code. "
        "Use 'Register new archive' to create one, or 'Retrieve archive' to switch to another.");
}

// ─────────────────────────────────────────────
//  DASHBOARD
// ─────────────────────────────────────────────
void renderDashboard(AppState& state) {
    ImGuiIO& io = ImGui::GetIO();
    ImGui::SetNextWindowSize(io.DisplaySize, ImGuiCond_Always);
    ImGui::SetNextWindowPos(ImVec2(0, 0), ImGuiCond_Always);
    ImGui::Begin("##dashboard", nullptr,
        ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove);

    // ── Sidebar ───────────────────────────────────────────
    ImGui::BeginChild("##sidebar", ImVec2(260, 0), true);

    ImGui::Spacing();
    ImGui::SetWindowFontScale(1.25f);
    ImGui::TextColored(Theme::AccentStrong(), "DocTracker");
    ImGui::SetWindowFontScale(1.0f);
    ImGui::TextDisabled("Archive:");
    ImGui::TextWrapped("%s", state.currentProjectTitle.c_str());
    ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();

    auto tabBtn = [&](const char* label, Tab t) {
        bool active = (state.tab == t);
        if (active) PushActiveTabButton();
        if (ImGui::Button(label, ImVec2(-1, 40))) state.tab = t;
        if (active) ImGui::PopStyleColor(4);
        ImGui::Spacing();
    };

    tabBtn("  Catalog",      Tab::CATALOG);
    tabBtn("  Acquisitions", Tab::ACQUISITIONS);
    ImGui::Spacing();
    tabBtn("  Metrics",      Tab::METRICS);
    tabBtn("  Activity log", Tab::LOG);
    ImGui::Spacing();
    tabBtn("  Guide",        Tab::GUIDE);

    ImGui::Separator(); ImGui::Spacing();
    ImGui::TextDisabled("Archive management");
    ImGui::Spacing();
    if (ImGui::Button("+ Add New Archive", ImVec2(0, 0)))
        state.confirmModal = ConfirmModal::NEW_DOC;
    ImGui::Spacing();
    if (ImGui::Button("Retrieve Archive", ImVec2(0, 0)))
        state.confirmModal = ConfirmModal::OPEN_OTHER;

    ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
    PushDangerButton();
    if (ImGui::Button("Logout", ImVec2(-1, 0)))
        state.confirmModal = ConfirmModal::LOGOUT;
    ImGui::PopStyleColor(3);

    ImGui::EndChild();
    ImGui::SameLine();

    // ── Content ───────────────────────────────────────────
    ImGui::BeginChild("##content", ImVec2(0, 0), false);
    ImGui::Spacing();

    switch (state.tab) {
        case Tab::CATALOG:      renderCatalog(state);      break;
        case Tab::ACQUISITIONS: renderAcquisitions(state); break;
        case Tab::METRICS:      renderMetrics(state);      break;
        case Tab::LOG:          renderLog(state);          break;
        case Tab::GUIDE:        renderGuide(state);        break;
    }

    ImGui::EndChild();

    // ── Top-level modals ──────────────────────────────────
    if (state.confirmModal == ConfirmModal::LOGOUT){
        ImGui::OpenPopup("##confirmlogout");
        state.confirmModal = ConfirmModal::NONE;
    }
    if (renderConfirmModal("##confirmlogout",
            "Log out?",
            "\nYour archive will be closed. \nYou can reopen it anytime.",
            "Logout", false))
    {
        clearSession(state);
        state.screen = Screen::LOGIN;
    }

    if (state.confirmModal == ConfirmModal::NEW_DOC){
        ImGui::OpenPopup("##confirmnew");
        state.confirmModal = ConfirmModal::NONE; 
    }
    if (renderConfirmModal("##confirmnew",
            "Register new archive?",
            "\nYou will be taken to the login screen to create a new archive.",
            "Continue", false))
    {
        clearSession(state);
        state.loginMode = false;
        state.screen    = Screen::LOGIN;
    }

    if (state.confirmModal == ConfirmModal::OPEN_OTHER){
        ImGui::OpenPopup("##confirmother");
        state.confirmModal = ConfirmModal::NONE;
    }
    if (renderConfirmModal("##confirmother",
            "Retrieve another archive?",
            "\nYour current session will close. \nUnsaved changes will be lost.",
            "Continue", false))
    {
        clearSession(state);
        state.loginMode = true;
        state.screen    = Screen::LOGIN;
    }

    ImGui::End();
}

// ─────────────────────────────────────────────
//  ENTRY POINT
// ─────────────────────────────────────────────
int main() {
    glfwInit();
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
#ifdef __APPLE__
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);
#endif

    GLFWwindow* window = glfwCreateWindow(1280, 800, "DocTracker", nullptr, nullptr);
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    io.Fonts->AddFontDefault();
    ImFontConfig cfg;
    cfg.SizePixels = 23.0f;
    io.Fonts->AddFontDefault(&cfg);
    io.FontDefault = io.Fonts->Fonts[1];

    ApplyLibraryTheme();

    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 330");

    initDB();
    AppState state;

    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        if (state.screen == Screen::LOGIN)
            renderLogin(state);
        else
            renderDashboard(state);

        ImGui::Render();

        int dispW, dispH;
        glfwGetFramebufferSize(window, &dispW, &dispH);
        glViewport(0, 0, dispW, dispH);

        ImVec4 bg = Theme::WindowBg();
        glClearColor(bg.x, bg.y, bg.z, bg.w);
        glClear(GL_COLOR_BUFFER_BIT);

        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(window);
    }

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    sqlite3_close(db);
    glfwDestroyWindow(window);
    glfwTerminate();
    return 0;
}