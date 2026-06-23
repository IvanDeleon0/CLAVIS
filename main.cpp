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

// ─────────────────────────────────────────────
//  XOR "encryption" – NOT real encryption.
//  Replace with AES-256 for production.
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

// ─────────────────────────────────────────────
//  djb2 hash – NOT a secure password hash.
//  Replace with bcrypt/Argon2 for production.
// ─────────────────────────────────────────────
std::string hashPassword(const std::string& password) {
    unsigned long hash = 5381;
    for (char c : password)
        hash = ((hash << 5) + hash) + c;
    std::ostringstream oss;
    oss << hash;
    return oss.str();
}

// ─────────────────────────────────────────────
//  Timestamp helper
// ─────────────────────────────────────────────
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

// ─────────────────────────────────────────────
//  App State
// ─────────────────────────────────────────────
enum class Screen { LOGIN, DASHBOARD };
enum class Tab    { DOCS, ADD_RECORD, STATS, ACTIVITY, HELP };

// Which confirm modal is open
enum class ConfirmModal { NONE, LOGOUT, DELETE_DOC, NEW_DOC, OPEN_OTHER };

struct AppState {
    Screen screen = Screen::LOGIN;
    Tab    tab    = Tab::DOCS;

    // login fields
    char projectTitle[128] = {};
    char securityCode[128] = {};
    bool authError   = false;
    bool loginMode   = true;

    // session
    int  currentProjectId = -1;
    std::string currentProjectTitle;

    // documents / records
    std::vector<Document> documents;
    char searchBuf[128] = {};

    int viewDocId = -1;

    // add/edit record
    bool editMode  = false;
    int  editDocId = -1;
    char docTitle[256]    = {};
    char docContent[4096] = {};
    char docTag[64]       = {};

    // activity
    std::vector<ActivityEntry> activity;

    // stats
    int totalDocs  = 0;
    int taggedDocs = 0;
    std::string lastModified;

    // confirm modals
    ConfirmModal confirmModal    = ConfirmModal::NONE;
    int          confirmDeleteId = -1;
    std::string  confirmDeleteTitle;
};

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
        "INSERT INTO activity (project_id, action, timestamp) VALUES (?1, ?2, ?3);",
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
    sqlite3_prepare_v2(db, "SELECT id FROM projects WHERE title=?1 AND password=?2;",
                       -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, title.c_str(),  -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, hashed.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt) == SQLITE_ROW)
        foundId = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return foundId;
}

int signupProject(const std::string& title, const std::string& code) {
    std::string hashed = hashPassword(code);
    std::string ts     = getTimestamp();
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db,
        "INSERT OR IGNORE INTO projects (title, password, created) VALUES (?1,?2,?3);",
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
        "SELECT id, title, content, tag, last_modified FROM documents "
        "WHERE project_id=?1 ORDER BY last_modified DESC;",
        -1, &stmt, nullptr);
    sqlite3_bind_int(stmt, 1, state.currentProjectId);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Document d;
        d.id           = sqlite3_column_int(stmt, 0);
        d.title        = reinterpret_cast<const char*>(sqlite3_column_text(stmt,1) ? sqlite3_column_text(stmt,1) : (const unsigned char*)"");
        d.content      = reinterpret_cast<const char*>(sqlite3_column_text(stmt,2) ? sqlite3_column_text(stmt,2) : (const unsigned char*)"");
        d.tag          = reinterpret_cast<const char*>(sqlite3_column_text(stmt,3) ? sqlite3_column_text(stmt,3) : (const unsigned char*)"");
        d.lastModified = reinterpret_cast<const char*>(sqlite3_column_text(stmt,4) ? sqlite3_column_text(stmt,4) : (const unsigned char*)"");
        state.documents.push_back(d);
    }
    sqlite3_finalize(stmt);
}

void loadActivity(AppState& state) {
    state.activity.clear();
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db,
        "SELECT action, timestamp FROM activity "
        "WHERE project_id=?1 ORDER BY id DESC LIMIT 50;",
        -1, &stmt, nullptr);
    sqlite3_bind_int(stmt, 1, state.currentProjectId);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        ActivityEntry a;
        a.action    = reinterpret_cast<const char*>(sqlite3_column_text(stmt,0) ? sqlite3_column_text(stmt,0) : (const unsigned char*)"");
        a.timestamp = reinterpret_cast<const char*>(sqlite3_column_text(stmt,1) ? sqlite3_column_text(stmt,1) : (const unsigned char*)"");
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

    sqlite3_stmt* stmt = nullptr;
    if (state.editMode && state.editDocId >= 0) {
        sqlite3_prepare_v2(db,
            "UPDATE documents SET title=?1, content=?2, tag=?3, last_modified=?4 WHERE id=?5;",
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
            "INSERT INTO documents (project_id, title, content, tag, last_modified) VALUES (?1,?2,?3,?4,?5);",
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

static void clearSession(AppState& state) {
    state.currentProjectId = -1;
    state.currentProjectTitle.clear();
    memset(state.securityCode, 0, sizeof(state.securityCode));
    memset(state.projectTitle, 0, sizeof(state.projectTitle));
    state.documents.clear();
    state.activity.clear();
    state.authError      = false;
    state.confirmModal   = ConfirmModal::NONE;
    state.viewDocId      = -1;
}

// ─────────────────────────────────────────────
//  Helper: centered text
// ─────────────────────────────────────────────
static void CenteredText(const char* text, ImVec4 color, bool colored = true) {
    float w = ImGui::GetWindowSize().x;
    float t = ImGui::CalcTextSize(text).x;
    ImGui::SetCursorPosX((w - t) * 0.5f);
    if (colored) ImGui::TextColored(color, "%s", text);
    else         ImGui::TextDisabled("%s", text);
}

// ─────────────────────────────────────────────
//  Confirm modal helper
//  Returns true when the user clicks "Yes, confirm".
//  Pass warningColor=true to tint the confirm button red.
// ─────────────────────────────────────────────
static bool renderConfirmModal(const char* popupId,
                               const char* title,
                               const char* message,
                               const char* confirmLabel = "Yes, proceed",
                               bool        dangerBtn   = true)
{
    bool confirmed = false;

    // Size scaled for the bigger font
    ImGui::SetNextWindowSize(ImVec2(560, 300), ImGuiCond_Always);
    ImGui::SetNextWindowPos(
        ImVec2(ImGui::GetIO().DisplaySize.x * 0.5f,
               ImGui::GetIO().DisplaySize.y * 0.5f),
        ImGuiCond_Always, ImVec2(0.5f, 0.5f));

    if (ImGui::BeginPopupModal(popupId, nullptr,
            ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
            ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse)) {

        // Icon + title row
        ImGui::Spacing();
        ImGui::SetWindowFontScale(1.25f);
        ImVec4 titleColor = dangerBtn
            ? ImVec4(1.0f, 0.38f, 0.38f, 1.0f)
            : ImVec4(0.35f, 0.65f, 1.0f, 1.0f);
        CenteredText(title, titleColor);
        ImGui::SetWindowFontScale(1.0f);

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing(); ImGui::Spacing();

        // Message
        float msgW = ImGui::CalcTextSize(message).x;
        ImGui::SetCursorPosX((560.0f - msgW) * 0.5f);
        ImGui::TextUnformatted(message);

        ImGui::Spacing(); ImGui::Spacing(); ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // Buttons – centred
        float btnW  = 170.0f;
        float gap   = 18.0f;
        float startX = (560.0f - btnW * 2 - gap) * 0.5f;
        ImGui::SetCursorPosX(startX);

        // Cancel (safe, blue-ish)
        ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.18f, 0.22f, 0.38f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.25f, 0.35f, 0.55f, 1.0f));
        if (ImGui::Button("Cancel", ImVec2(btnW, 42))) {
            ImGui::CloseCurrentPopup();
        }
        ImGui::PopStyleColor(2);

        ImGui::SameLine(0, gap);

        // Confirm (danger red or normal blue)
        if (dangerBtn) {
            ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.75f, 0.18f, 0.18f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.90f, 0.25f, 0.25f, 1.0f));
        } else {
            ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.15f, 0.50f, 0.85f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.20f, 0.65f, 1.00f, 1.0f));
        }
        if (ImGui::Button(confirmLabel, ImVec2(btnW, 42))) {
            confirmed = true;
            ImGui::CloseCurrentPopup();
        }
        ImGui::PopStyleColor(2);

        ImGui::EndPopup();
    }
    return confirmed;
}

// ─────────────────────────────────────────────
//  LOGIN SCREEN
// ─────────────────────────────────────────────
void renderLogin(AppState& state) {
    ImGuiIO& io = ImGui::GetIO();
    float W = io.DisplaySize.x;
    float H = io.DisplaySize.y;

    ImGui::SetNextWindowSize(ImVec2(W, H), ImGuiCond_Always);
    ImGui::SetNextWindowPos(ImVec2(0, 0), ImGuiCond_Always);
    ImGui::Begin("##bg", nullptr,
        ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove     | ImGuiWindowFlags_NoScrollbar |
        ImGuiWindowFlags_NoBringToFrontOnFocus);

    // Card is wider/taller to absorb the bigger base font
    const float CARD_W = 680.0f;
    const float CARD_H = 680.0f;
    float cardX = (W - CARD_W) * 0.5f;
    float cardY = (H - CARD_H) * 0.28f;

    ImGui::SetNextWindowSize(ImVec2(CARD_W, CARD_H), ImGuiCond_Always);
    ImGui::SetNextWindowPos(ImVec2(cardX, cardY), ImGuiCond_Always);
    ImGui::SetNextWindowBgAlpha(1.0f);
    ImGui::Begin("##logincard", nullptr,
        ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove     | ImGuiWindowFlags_NoScrollbar |
        ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoScrollWithMouse);

    ImGui::Spacing(); ImGui::Spacing();

    // ── App title  (base font * 1.7 * 1.5 ≈ display headline)
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.35f, 0.65f, 1.0f, 1.0f));
    ImGui::SetWindowFontScale(1.5f);
    CenteredText("DocTracker", ImVec4(0.35f, 0.65f, 1.0f, 1.0f));
    ImGui::SetWindowFontScale(1.0f);
    ImGui::PopStyleColor();

    ImGui::Spacing();
    CenteredText("Project Documentation Manager", ImVec4(1,1,1,1), false);
    ImGui::Spacing(); ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing(); ImGui::Spacing();

    // ── Toggle buttons
    float toggleW = 270.0f;
    ImGui::SetCursorPosX((CARD_W - toggleW * 2 - 10) * 0.5f);

    ImGui::PushStyleColor(ImGuiCol_Button,
        state.loginMode ? ImVec4(0.2f,0.4f,0.85f,1.0f) : ImVec4(0.18f,0.22f,0.35f,1.0f));
    if (ImGui::Button("Open Documentation", ImVec2(toggleW, 44))) {
        state.loginMode = true; state.authError = false;
    }
    ImGui::PopStyleColor();

    ImGui::SameLine(0, 10);

    ImGui::PushStyleColor(ImGuiCol_Button,
        !state.loginMode ? ImVec4(0.2f,0.4f,0.85f,1.0f) : ImVec4(0.18f,0.22f,0.35f,1.0f));
    if (ImGui::Button("Create New Documentation", ImVec2(toggleW, 44))) {
        state.loginMode = false; state.authError = false;
    }
    ImGui::PopStyleColor();

    ImGui::Spacing(); ImGui::Spacing();

    float inputX = (CARD_W - 560.0f) * 0.5f;

    ImGui::SetCursorPosX(inputX);
    ImGui::Text("Documentation Name");
    ImGui::SetCursorPosX(inputX);
    ImGui::SetNextItemWidth(560.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(12, 12));
    ImGui::InputText("##title", state.projectTitle, sizeof(state.projectTitle));
    ImGui::PopStyleVar();

    ImGui::Spacing(); ImGui::Spacing();

    ImGui::SetCursorPosX(inputX);
    ImGui::Text("Security Code");
    ImGui::SetCursorPosX(inputX);
    ImGui::SetNextItemWidth(560.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(12, 12));
    ImGui::InputText("##code", state.securityCode, sizeof(state.securityCode),
                     ImGuiInputTextFlags_Password);
    ImGui::PopStyleVar();

    ImGui::Spacing();
    if (state.authError) {
        ImGui::SetCursorPosX(inputX);
        ImGui::TextColored(ImVec4(1.0f,0.35f,0.35f,1.0f),
            state.loginMode
                ? "  Incorrect name or security code. Try again."
                : "  That name is already taken. Choose another.");
    }

    ImGui::Spacing(); ImGui::Spacing();

    float bigBtnW = 560.0f;
    ImGui::SetCursorPosX((CARD_W - bigBtnW) * 0.5f);
    ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.15f, 0.55f, 0.90f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.20f, 0.65f, 1.00f, 1.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(12, 14));
    ImGui::SetWindowFontScale(1.1f);

    bool doAction = ImGui::Button(
        state.loginMode ? "Open  ->" : "Create  ->",
        ImVec2(bigBtnW, 52));

    ImGui::SetWindowFontScale(1.0f);
    ImGui::PopStyleVar();
    ImGui::PopStyleColor(2);

    if (doAction) {
        if (state.loginMode) {
            int id = loginProject(state.projectTitle, state.securityCode);
            if (id >= 0) {
                state.currentProjectId    = id;
                state.currentProjectTitle = state.projectTitle;
                state.authError = false;
                state.screen    = Screen::DASHBOARD;
                state.tab       = Tab::DOCS;
                loadDocuments(state);
                loadActivity(state);
                computeStats(state);
                logActivity(id, "Opened documentation");
            } else {
                state.authError = true;
            }
        } else {
            if (strlen(state.projectTitle) > 0 && strlen(state.securityCode) > 0) {
                int id = signupProject(state.projectTitle, state.securityCode);
                if (id >= 0) {
                    state.currentProjectId    = id;
                    state.currentProjectTitle = state.projectTitle;
                    state.authError = false;
                    state.screen    = Screen::DASHBOARD;
                    state.tab       = Tab::DOCS;
                    loadDocuments(state);
                    loadActivity(state);
                    computeStats(state);
                    logActivity(id, "Created documentation");
                } else {
                    state.authError = true;
                }
            }
        }
    }

    ImGui::End(); // card

    // Quote strip below card
    float quoteY = cardY + CARD_H + 32.0f;
    if (quoteY + 90.0f < H) {
        ImGui::SetNextWindowSize(ImVec2(W, H - quoteY), ImGuiCond_Always);
        ImGui::SetNextWindowPos(ImVec2(0, quoteY), ImGuiCond_Always);
        ImGui::SetNextWindowBgAlpha(0.0f);
        ImGui::Begin("##quote", nullptr,
            ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
            ImGuiWindowFlags_NoMove     | ImGuiWindowFlags_NoScrollbar |
            ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoBringToFrontOnFocus);

        ImGui::Spacing(); ImGui::Spacing();
        CenteredText("\" Documentation is your lifeline --", ImVec4(0.55f,0.60f,0.75f,0.85f));
        CenteredText("  the bridge between today's clarity and tomorrow's confusion. \"",
                     ImVec4(0.55f,0.60f,0.75f,0.85f));
        ImGui::Spacing();
        CenteredText("Write it now. Thank yourself later.", ImVec4(0.40f,0.50f,0.70f,0.65f));
        ImGui::End();
    }

    ImGui::End(); // full-screen bg
}

// ─────────────────────────────────────────────
//  DASHBOARD
// ─────────────────────────────────────────────
void renderDashboard(AppState& state) {
    ImGuiIO& io = ImGui::GetIO();
    ImGui::SetNextWindowSize(io.DisplaySize, ImGuiCond_Always);
    ImGui::SetNextWindowPos(ImVec2(0, 0), ImGuiCond_Always);
    ImGui::Begin("##dashboard", nullptr,
        ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove     | ImGuiWindowFlags_NoBringToFrontOnFocus |
        ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

    // ── Sidebar – no scroll, everything laid out sequentially ──
    ImGui::BeginChild("##sidebar", ImVec2(260, 0), true,
        ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

    ImGui::SetWindowFontScale(1.2f);
    ImGui::TextColored(ImVec4(0.35f, 0.65f, 1.0f, 1.0f), "DocTracker");
    ImGui::SetWindowFontScale(1.0f);
    ImGui::Spacing();
    ImGui::TextDisabled("Documentation:");
    ImGui::TextWrapped("%s", state.currentProjectTitle.c_str());
    ImGui::Separator(); ImGui::Spacing();

    auto tabBtn = [&](const char* label, Tab t) {
        bool active = state.tab == t;
        if (active) ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.20f,0.40f,0.80f,1.0f));
        if (ImGui::Button(label, ImVec2(-1, 40))) state.tab = t;
        if (active) ImGui::PopStyleColor();
        ImGui::Spacing();
    };
    tabBtn("Records",      Tab::DOCS);
    tabBtn("Add Record",   Tab::ADD_RECORD);
    tabBtn("Statistics",   Tab::STATS);
    tabBtn("Activity Log", Tab::ACTIVITY);
    tabBtn("Help",         Tab::HELP);

    ImGui::Separator();
    ImGui::Spacing();
    ImGui::TextDisabled("Switch documentation:");
    ImGui::Spacing();

    if (ImGui::Button("+ New Documentation", ImVec2(-1, 38)))
        state.confirmModal = ConfirmModal::NEW_DOC;
    ImGui::Spacing();

    if (ImGui::Button("Open Other Docs", ImVec2(-1, 38)))
        state.confirmModal = ConfirmModal::OPEN_OTHER;

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.55f,0.15f,0.15f,1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.75f,0.20f,0.20f,1.0f));
    if (ImGui::Button("Logout", ImVec2(-1, 38)))
        state.confirmModal = ConfirmModal::LOGOUT;
    ImGui::PopStyleColor(2);

    ImGui::EndChild();
    ImGui::SameLine();

    // ── Main Content ──
    ImGui::BeginChild("##content", ImVec2(0, 0), false);

    // ── TAB: RECORDS ──
    if (state.tab == Tab::DOCS) {
        std::string search = state.searchBuf;

        ImGui::Spacing();
        ImGui::SetNextItemWidth(380.0f);
        ImGui::InputText("Search##search", state.searchBuf, sizeof(state.searchBuf));
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // Delete pending – track outside the loop, execute after
        bool        pendingDelete = false;
        int         pendingId     = -1;
        std::string pendingTitle;

        for (auto& d : state.documents) {
            if (!search.empty() && d.title.find(search) == std::string::npos) continue;

            ImGui::PushID(d.id);

            // Card background via a colored group rect
            ImVec2 cardMin = ImGui::GetCursorScreenPos();
            float  availW  = ImGui::GetContentRegionAvail().x;
            float  cardH   = ImGui::GetTextLineHeight() * 2 + ImGui::GetStyle().ItemSpacing.y * 3
                             + ImGui::GetStyle().FramePadding.y * 2 + 4.0f;

            // Draw filled card background
            ImGui::GetWindowDrawList()->AddRectFilled(
                cardMin,
                ImVec2(cardMin.x + availW, cardMin.y + cardH + 14.0f),
                IM_COL32(36, 38, 52, 255), 7.0f);

            ImGui::Spacing();
            ImGui::Indent(10.0f);
            ImGui::TextUnformatted(d.title.c_str());
            ImGui::TextDisabled("Last modified: %s", d.lastModified.c_str());
            ImGui::Unindent(10.0f);

            // Buttons on the right of the SAME line as the text block
            // We jump to the right side using SameLine with an absolute offset
            float btnAreaW = 94.0f * 3 + 6.0f * 2 + 10.0f; // 3 buttons + gaps + margin
            ImGui::SameLine(availW - btnAreaW);
            // vertically centre buttons: nudge down half the card height
            float btnY = cardMin.y + (cardH + 14.0f) * 0.5f - ImGui::GetFrameHeight() * 0.5f;
            ImGui::SetCursorPosY(btnY - ImGui::GetWindowPos().y + ImGui::GetScrollY());

            if (ImGui::Button("View", ImVec2(94, 0)))
                state.viewDocId = d.id;

            ImGui::SameLine(0, 6);
            if (ImGui::Button("Edit", ImVec2(94, 0))) {
                clearAddEdit(state);
                strncpy(state.docTitle,   d.title.c_str(),   sizeof(state.docTitle)   - 1);
                state.docTitle  [sizeof(state.docTitle)   - 1] = '\0';
                strncpy(state.docContent, d.content.c_str(), sizeof(state.docContent) - 1);
                state.docContent[sizeof(state.docContent) - 1] = '\0';
                strncpy(state.docTag,     d.tag.c_str(),     sizeof(state.docTag)     - 1);
                state.docTag    [sizeof(state.docTag)     - 1] = '\0';
                state.editMode  = true;
                state.editDocId = d.id;
                state.tab = Tab::ADD_RECORD;
            }

            ImGui::SameLine(0, 6);
            ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.55f,0.15f,0.15f,1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.75f,0.20f,0.20f,1.0f));
            if (ImGui::Button("Delete", ImVec2(94, 0))) {
                state.confirmModal       = ConfirmModal::DELETE_DOC;
                state.confirmDeleteId    = d.id;
                state.confirmDeleteTitle = d.title;
            }
            ImGui::PopStyleColor(2);

            ImGui::PopID();

            // Gap between cards
            ImGui::Dummy(ImVec2(0, 8));
        }

        // ── Delete confirm modal ──
        if (state.confirmModal == ConfirmModal::DELETE_DOC) {
            ImGui::OpenPopup("##confirmDelete");
            std::string msg = "Delete \"" + state.confirmDeleteTitle + "\"? \n This cannot be undone.";
            if (renderConfirmModal("##confirmDelete",
                    "Delete Record",
                    msg.c_str(),
                    "Yes, Delete",
                    true)) {
                deleteDocument(state, state.confirmDeleteId, state.confirmDeleteTitle);
                state.confirmModal    = ConfirmModal::NONE;
                state.confirmDeleteId = -1;
                state.confirmDeleteTitle.clear();
            } else if (!ImGui::IsPopupOpen("##confirmDelete")) {
                // User hit Cancel or clicked outside
                state.confirmModal = ConfirmModal::NONE;
            }
        }

        // ── View modal ──
        if (state.viewDocId >= 0) {
            for (auto& d : state.documents) {
                if (d.id != state.viewDocId) continue;
                ImGui::OpenPopup("##viewmodal");
                ImGui::SetNextWindowSize(ImVec2(740, 560), ImGuiCond_Always);
                ImGui::SetNextWindowPos(
                    ImVec2(io.DisplaySize.x * 0.5f, io.DisplaySize.y * 0.5f),
                    ImGuiCond_Always, ImVec2(0.5f, 0.5f));
                if (ImGui::BeginPopupModal("##viewmodal", nullptr,
                        ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize)) {
                    ImGui::SetWindowFontScale(1.15f);
                    ImGui::TextColored(ImVec4(0.35f,0.65f,1.0f,1.0f), "%s", d.title.c_str());
                    ImGui::SetWindowFontScale(1.0f);
                    ImGui::TextDisabled("Last modified: %s", d.lastModified.c_str());
                    if (!d.tag.empty()) { ImGui::SameLine(); ImGui::TextDisabled("  [%s]", d.tag.c_str()); }
                    ImGui::Separator(); ImGui::Spacing();
                    float ch = ImGui::GetContentRegionAvail().y - 54.0f;
                    static char viewBuf[4096];
                    strncpy(viewBuf, d.content.c_str(), sizeof(viewBuf) - 1);
                    viewBuf[sizeof(viewBuf) - 1] = '\0';
                    ImGui::InputTextMultiline("##view_content",
                        viewBuf, sizeof(viewBuf),
                        ImVec2(-1, ch > 0 ? ch : 200),
                        ImGuiInputTextFlags_ReadOnly);
                    ImGui::Spacing();
                    if (ImGui::Button("Close", ImVec2(120, 42))) {
                        state.viewDocId = -1;
                        ImGui::CloseCurrentPopup();
                    }
                    ImGui::EndPopup();
                }
                break;
            }
        }
    }

    // ── TAB: ADD / EDIT RECORD ──
    else if (state.tab == Tab::ADD_RECORD) {
        ImGui::Spacing();
        ImGui::SetWindowFontScale(1.2f);
        ImGui::TextColored(ImVec4(0.35f, 0.65f, 1.0f, 1.0f),
            state.editMode ? "Edit Record" : "Add Record");
        ImGui::SetWindowFontScale(1.0f);
        ImGui::Separator(); ImGui::Spacing();

        ImGui::Text("Title");
        ImGui::SetNextItemWidth(-1);
        ImGui::InputText("##doctitle", state.docTitle, sizeof(state.docTitle));
        ImGui::Spacing();

        ImGui::Text("Tag (optional)");
        ImGui::SetNextItemWidth(300.0f);
        ImGui::InputText("##doctag", state.docTag, sizeof(state.docTag));
        ImGui::Spacing();

        ImGui::Text("Content");
        float contentH = ImGui::GetContentRegionAvail().y - 64.0f;
        ImGui::InputTextMultiline("##doccontent",
            state.docContent, sizeof(state.docContent),
            ImVec2(-1, contentH > 120 ? contentH : 120));
        ImGui::Spacing();

        if (ImGui::Button(state.editMode ? "Save Changes" : "Add Record", ImVec2(190, 44))) {
            if (strlen(state.docTitle) > 0) {
                saveDocument(state);
                clearAddEdit(state);
                state.tab = Tab::DOCS;
                loadActivity(state);
            }
        }
        ImGui::SameLine(0, 12);
        if (ImGui::Button("Cancel", ImVec2(120, 44))) {
            clearAddEdit(state);
            state.tab = Tab::DOCS;
        }
    }

    // ── TAB: STATS ──
    else if (state.tab == Tab::STATS) {
        ImGui::Spacing();
        ImGui::SetWindowFontScale(1.2f);
        ImGui::TextColored(ImVec4(0.35f, 0.65f, 1.0f, 1.0f), "Statistics");
        ImGui::SetWindowFontScale(1.0f);
        ImGui::Separator(); ImGui::Spacing();

        ImGui::Text("Documentation  : %s", state.currentProjectTitle.c_str());
        ImGui::Spacing();
        ImGui::Text("Total Records  : %d", state.totalDocs);
        ImGui::Text("Tagged         : %d", state.taggedDocs);
        ImGui::Text("Untagged       : %d", state.totalDocs - state.taggedDocs);
        ImGui::Spacing();
        if (!state.lastModified.empty())
            ImGui::Text("Last Modified  : %s", state.lastModified.c_str());

        ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
        ImGui::TextDisabled("Tags breakdown:");
        ImGui::Spacing();
        std::map<std::string,int> tagCount;
        for (auto& d : state.documents)
            tagCount[d.tag.empty() ? "(no tag)" : d.tag]++;
        for (auto& [tag, count] : tagCount)
            ImGui::Text("  %-24s  %d", tag.c_str(), count);
    }

    // ── TAB: ACTIVITY ──
    else if (state.tab == Tab::ACTIVITY) {
        ImGui::Spacing();
        ImGui::SetWindowFontScale(1.2f);
        ImGui::TextColored(ImVec4(0.35f, 0.65f, 1.0f, 1.0f), "Activity Log");
        ImGui::SetWindowFontScale(1.0f);
        ImGui::Separator(); ImGui::Spacing();

        for (auto& a : state.activity) {
            ImGui::TextDisabled("%s", a.timestamp.c_str());
            ImGui::SameLine(220);
            ImGui::Text("%s", a.action.c_str());
        }
        if (state.activity.empty())
            ImGui::TextDisabled("No activity yet.");
    }

    // ── TAB: HELP ──
    else if (state.tab == Tab::HELP) {
        ImGui::Spacing();
        ImGui::SetWindowFontScale(1.2f);
        ImGui::TextColored(ImVec4(0.35f, 0.65f, 1.0f, 1.0f), "Help");
        ImGui::SetWindowFontScale(1.0f);
        ImGui::Separator(); ImGui::Spacing();

        ImGui::TextWrapped("DocTracker lets you store and manage documentation sets securely. "
                           "Each documentation is protected by its own security code -- "
                           "other documentations remain fully locked while you work.");
        ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();

        ImGui::BulletText("Documentation Name  =  your project name (acts as username)");
        ImGui::BulletText("Security Code       =  your password (hashed before storing)");
        ImGui::BulletText("Records are encrypted with your security code");
        ImGui::BulletText("Each documentation is independent and separately secured");
        ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();

        ImGui::BulletText("Records tab       -- browse, search, view, delete records");
        ImGui::BulletText("Add Record tab    -- write new records or edit existing ones");
        ImGui::BulletText("Statistics tab    -- see counts and tag breakdown");
        ImGui::BulletText("Activity Log      -- see what was done and when");
        ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();

        ImGui::BulletText("Use 'Open Other Docs' in the sidebar to switch to another documentation");
        ImGui::BulletText("Use '+ New Documentation' to create and jump to a fresh one");
        ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();

        ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.2f, 1.0f), "Security note:");
        ImGui::TextWrapped("This version uses XOR encryption and djb2 hashing. "
                           "For production use, replace with AES-256 (OpenSSL) "
                           "and bcrypt/Argon2 password hashing.");
    }

    ImGui::EndChild(); // content

    // ═══════════════════════════════════════════
    //  Confirm modals rendered at dashboard level
    //  (so they appear over both sidebar & content)
    // ═══════════════════════════════════════════

    // ── Logout ──
    if (state.confirmModal == ConfirmModal::LOGOUT) {
        ImGui::OpenPopup("##confirmLogout");
        if (renderConfirmModal("##confirmLogout",
                "Logout",
                "Are you sure you want to log out?",
                "Yes, Logout", true)) {
            logActivity(state.currentProjectId, "Logged out");
            clearSession(state);
            state.screen    = Screen::LOGIN;
            state.loginMode = true;
        } else if (!ImGui::IsPopupOpen("##confirmLogout")) {
            state.confirmModal = ConfirmModal::NONE;
        }
    }

    // ── New Documentation ──
    if (state.confirmModal == ConfirmModal::NEW_DOC) {
        ImGui::OpenPopup("##confirmNewDoc");
        if (renderConfirmModal("##confirmNewDoc",
                "New Documentation",
                "Leave this documentation and create a new one?",
                "Yes, Continue", false)) {
            logActivity(state.currentProjectId, "Switched out");
            clearSession(state);
            state.screen    = Screen::LOGIN;
            state.loginMode = false;
        } else if (!ImGui::IsPopupOpen("##confirmNewDoc")) {
            state.confirmModal = ConfirmModal::NONE;
        }
    }

    // ── Open Other Docs ──
    if (state.confirmModal == ConfirmModal::OPEN_OTHER) {
        ImGui::OpenPopup("##confirmOpenOther");
        if (renderConfirmModal("##confirmOpenOther",
                "Switch Documentation",
                "Leave this documentation and open another one?",
                "Yes, Switch", false)) {
            logActivity(state.currentProjectId, "Switched out");
            clearSession(state);
            state.screen    = Screen::LOGIN;
            state.loginMode = true;
        } else if (!ImGui::IsPopupOpen("##confirmOpenOther")) {
            state.confirmModal = ConfirmModal::NONE;
        }
    }

    ImGui::End(); // dashboard
}

// ─────────────────────────────────────────────
//  MAIN
// ─────────────────────────────────────────────
int main() {
    glfwInit();
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);

    GLFWwindow* window = glfwCreateWindow(1280, 800, "DocTracker", nullptr, nullptr);
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();

    // ── Load default font at 1.7× size (~27 px) ──
    // This is the clean way to globally upsize all text without SetWindowFontScale chains.
    // Add fonts BEFORE backend Init; do NOT call Build() manually —
    // the backend (ImGui_ImplOpenGL3_Init) calls it automatically.
    io.Fonts->AddFontDefault();         // index 0 – fallback (13 px)
    ImFontConfig cfg;
    cfg.SizePixels = 23.0f;            // 13 px * ~1.7
    io.Fonts->AddFontDefault(&cfg);    // index 1 – big font

    ImGui::StyleColorsDark();
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 330");

    // Set default font AFTER Init so the atlas is ready
    io.FontDefault = io.Fonts->Fonts[1];

    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowRounding    = 10.0f;
    style.FrameRounding     = 7.0f;
    style.GrabRounding      = 7.0f;
    style.PopupRounding     = 7.0f;
    style.ChildRounding     = 8.0f;
    style.ItemSpacing       = ImVec2(10, 10);
    style.FramePadding      = ImVec2(10, 9);
    style.WindowPadding     = ImVec2(18, 16);

    style.Colors[ImGuiCol_WindowBg]       = ImVec4(0.09f, 0.09f, 0.12f, 1.0f);
    style.Colors[ImGuiCol_ChildBg]        = ImVec4(0.11f, 0.12f, 0.17f, 1.0f);
    style.Colors[ImGuiCol_Button]         = ImVec4(0.18f, 0.22f, 0.38f, 1.0f);
    style.Colors[ImGuiCol_ButtonHovered]  = ImVec4(0.25f, 0.35f, 0.65f, 1.0f);
    style.Colors[ImGuiCol_ButtonActive]   = ImVec4(0.20f, 0.45f, 0.80f, 1.0f);
    style.Colors[ImGuiCol_FrameBg]        = ImVec4(0.15f, 0.16f, 0.22f, 1.0f);
    style.Colors[ImGuiCol_FrameBgHovered] = ImVec4(0.20f, 0.22f, 0.30f, 1.0f);
    style.Colors[ImGuiCol_Header]         = ImVec4(0.20f, 0.30f, 0.55f, 1.0f);
    style.Colors[ImGuiCol_Separator]      = ImVec4(0.25f, 0.27f, 0.38f, 1.0f);
    style.Colors[ImGuiCol_ScrollbarBg]    = ImVec4(0.09f, 0.09f, 0.12f, 1.0f);
    style.Colors[ImGuiCol_ScrollbarGrab]  = ImVec4(0.25f, 0.30f, 0.50f, 1.0f);

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
        int W, H;
        glfwGetFramebufferSize(window, &W, &H);
        glViewport(0, 0, W, H);
        glClearColor(0.09f, 0.09f, 0.12f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(window);
    }

    sqlite3_close(db);
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();
    return 0;
}