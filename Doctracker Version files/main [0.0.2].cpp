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
//  XOR "encryption" for stored content
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
//  djb2 hash for passwords
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

struct AppState {
    Screen screen = Screen::LOGIN;
    Tab    tab    = Tab::DOCS;

    // login fields
    char projectTitle[128] = {};
    char securityCode[128] = {};
    bool authError   = false;
    bool loginMode   = true;   // true = login, false = create new documentation

    // session
    int  currentProjectId = -1;
    std::string currentProjectTitle;
    std::string currentSecurityCode;

    // documents / records
    std::vector<Document> documents;
    char searchBuf[128] = {};

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
        ");",
        nullptr, nullptr, nullptr);
    sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS documents ("
        "  id            INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  project_id    INTEGER NOT NULL,"
        "  title         TEXT NOT NULL,"
        "  content       TEXT NOT NULL,"
        "  tag           TEXT,"
        "  last_modified TEXT NOT NULL,"
        "  FOREIGN KEY(project_id) REFERENCES projects(id)"
        ");",
        nullptr, nullptr, nullptr);
    sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS activity ("
        "  id         INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  project_id INTEGER NOT NULL,"
        "  action     TEXT NOT NULL,"
        "  timestamp  TEXT NOT NULL"
        ");",
        nullptr, nullptr, nullptr);
}

void logActivity(int projectId, const std::string& action) {
    std::string ts  = getTimestamp();
    std::string sql = "INSERT INTO activity (project_id, action, timestamp) VALUES ("
                      + std::to_string(projectId) + ", '" + action + "', '" + ts + "');";
    sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr);
}

int loginProject(const std::string& title, const std::string& code) {
    std::string hashed = hashPassword(code);
    std::string sql = "SELECT id FROM projects WHERE title='" + title
                    + "' AND password='" + hashed + "';";
    int foundId = -1;
    sqlite3_exec(db, sql.c_str(),
        [](void* data, int, char** argv, char**) -> int {
            *(int*)data = std::stoi(argv[0]);
            return 0;
        }, &foundId, nullptr);
    return foundId;
}

int signupProject(const std::string& title, const std::string& code) {
    std::string hashed = hashPassword(code);
    std::string ts     = getTimestamp();
    std::string sql = "INSERT OR IGNORE INTO projects (title, password, created) VALUES ('"
                    + title + "', '" + hashed + "', '" + ts + "');";
    sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr);
    return loginProject(title, code);
}

void loadDocuments(AppState& state) {
    state.documents.clear();
    std::string sql = "SELECT id, title, content, tag, last_modified FROM documents "
                      "WHERE project_id=" + std::to_string(state.currentProjectId)
                    + " ORDER BY last_modified DESC;";
    sqlite3_exec(db, sql.c_str(),
        [](void* data, int, char** argv, char**) -> int {
            auto* docs = (std::vector<Document>*)data;
            Document d;
            d.id           = std::stoi(argv[0]);
            d.title        = argv[1] ? argv[1] : "";
            d.content      = argv[2] ? argv[2] : "";
            d.tag          = argv[3] ? argv[3] : "";
            d.lastModified = argv[4] ? argv[4] : "";
            docs->push_back(d);
            return 0;
        }, &state.documents, nullptr);

    for (auto& d : state.documents)
        d.content = xorDecrypt(d.content, state.currentSecurityCode);
}

void loadActivity(AppState& state) {
    state.activity.clear();
    std::string sql = "SELECT action, timestamp FROM activity "
                      "WHERE project_id=" + std::to_string(state.currentProjectId)
                    + " ORDER BY id DESC LIMIT 50;";
    sqlite3_exec(db, sql.c_str(),
        [](void* data, int, char** argv, char**) -> int {
            auto* act = (std::vector<ActivityEntry>*)data;
            act->push_back({argv[0] ? argv[0] : "", argv[1] ? argv[1] : ""});
            return 0;
        }, &state.activity, nullptr);
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
    std::string content = xorEncrypt(state.docContent, state.currentSecurityCode);
    std::string tag     = state.docTag;
    std::string ts      = getTimestamp();

    if (state.editMode && state.editDocId >= 0) {
        std::string sql = "UPDATE documents SET title='" + title
                        + "', content='" + content
                        + "', tag='" + tag
                        + "', last_modified='" + ts
                        + "' WHERE id=" + std::to_string(state.editDocId) + ";";
        sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr);
        logActivity(state.currentProjectId, "Edited record: " + title);
    } else {
        std::string sql = "INSERT INTO documents (project_id, title, content, tag, last_modified) VALUES ("
                        + std::to_string(state.currentProjectId) + ", '"
                        + title + "', '" + content + "', '" + tag + "', '" + ts + "');";
        sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr);
        logActivity(state.currentProjectId, "Added record: " + title);
    }
    loadDocuments(state);
    computeStats(state);
}

void deleteDocument(AppState& state, int docId, const std::string& docTitle) {
    std::string sql = "DELETE FROM documents WHERE id=" + std::to_string(docId) + ";";
    sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr);
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

// ─────────────────────────────────────────────
//  Helper: centered text
// ─────────────────────────────────────────────
static void CenteredText(const char* text, ImVec4 color, bool colored = true) {
    float windowWidth = ImGui::GetWindowSize().x;
    float textWidth   = ImGui::CalcTextSize(text).x;
    ImGui::SetCursorPosX((windowWidth - textWidth) * 0.5f);
    if (colored)
        ImGui::TextColored(color, "%s", text);
    else
        ImGui::TextDisabled("%s", text);
}

// ─────────────────────────────────────────────
//  LOGIN SCREEN  — big, readable, spacious
// ─────────────────────────────────────────────
void renderLogin(AppState& state) {
    ImGuiIO& io = ImGui::GetIO();
    float W = io.DisplaySize.x;
    float H = io.DisplaySize.y;

    // Full-screen background window
    ImGui::SetNextWindowSize(ImVec2(W, H), ImGuiCond_Always);
    ImGui::SetNextWindowPos(ImVec2(0, 0), ImGuiCond_Always);
    ImGui::Begin("##bg", nullptr,
                 ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                 ImGuiWindowFlags_NoMove     | ImGuiWindowFlags_NoScrollbar |
                 ImGuiWindowFlags_NoBringToFrontOnFocus);

    // ── Card dimensions ──
    const float CARD_W = 560.0f;
    const float CARD_H = 560.0f;
    float cardX = (W - CARD_W) * 0.5f;
    float cardY = (H - CARD_H) * 0.35f;   // slightly above center

    // ── Card popup ──
    ImGui::SetNextWindowSize(ImVec2(CARD_W, CARD_H), ImGuiCond_Always);
    ImGui::SetNextWindowPos(ImVec2(cardX, cardY), ImGuiCond_Always);
    ImGui::SetNextWindowBgAlpha(1.0f);
    ImGui::Begin("##logincard", nullptr,
                 ImGuiWindowFlags_NoTitleBar  | ImGuiWindowFlags_NoResize |
                 ImGuiWindowFlags_NoMove      | ImGuiWindowFlags_NoScrollbar |
                 ImGuiWindowFlags_NoSavedSettings);

    ImGui::Spacing(); ImGui::Spacing();

    // Title
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.35f, 0.65f, 1.0f, 1.0f));
    ImGui::SetWindowFontScale(1.9f);
    CenteredText("DocTracker", ImVec4(0.35f, 0.65f, 1.0f, 1.0f));
    ImGui::SetWindowFontScale(1.0f);
    ImGui::PopStyleColor();

    ImGui::Spacing();
    ImGui::SetWindowFontScale(1.05f);
    CenteredText("Project Documentation Manager", ImVec4(1,1,1,1), false);
    ImGui::SetWindowFontScale(1.0f);
    ImGui::Spacing(); ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing(); ImGui::Spacing();

    // ── Toggle: Login / Create New Documentation ──
    float toggleW = 240.0f;
    ImGui::SetCursorPosX((CARD_W - toggleW * 2 - 10) * 0.5f);

    if (state.loginMode)
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.2f, 0.4f, 0.85f, 1.0f));
    else
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.18f, 0.22f, 0.35f, 1.0f));
    if (ImGui::Button("Open Documentation", ImVec2(toggleW, 38))) {
        state.loginMode = true;
        state.authError = false;
    }
    ImGui::PopStyleColor();
    ImGui::SameLine(0, 10);
    if (!state.loginMode)
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.2f, 0.4f, 0.85f, 1.0f));
    else
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.18f, 0.22f, 0.35f, 1.0f));
    if (ImGui::Button("Create New Documentation", ImVec2(toggleW, 38))) {
        state.loginMode = false;
        state.authError = false;
    }
    ImGui::PopStyleColor();

    ImGui::Spacing(); ImGui::Spacing();

    // ── Input fields ──
    float inputX = (CARD_W - 460.0f) * 0.5f;

    ImGui::SetCursorPosX(inputX);
    ImGui::SetWindowFontScale(1.05f);
    ImGui::Text("Documentation Name");
    ImGui::SetWindowFontScale(1.0f);
    ImGui::SetCursorPosX(inputX);
    ImGui::SetNextItemWidth(460.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(12, 10));
    ImGui::InputText("##title", state.projectTitle, sizeof(state.projectTitle));
    ImGui::PopStyleVar();

    ImGui::Spacing(); ImGui::Spacing();

    ImGui::SetCursorPosX(inputX);
    ImGui::SetWindowFontScale(1.05f);
    ImGui::Text("Security Code");
    ImGui::SetWindowFontScale(1.0f);
    ImGui::SetCursorPosX(inputX);
    ImGui::SetNextItemWidth(460.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(12, 10));
    ImGui::InputText("##code", state.securityCode, sizeof(state.securityCode),
                     ImGuiInputTextFlags_Password);
    ImGui::PopStyleVar();

    ImGui::Spacing();

    if (state.authError) {
        ImGui::SetCursorPosX(inputX);
        ImGui::TextColored(ImVec4(1.0f, 0.35f, 0.35f, 1.0f),
            state.loginMode
                ? "  Incorrect name or security code. Try again."
                : "  That name is already taken. Choose another.");
    }

    ImGui::Spacing(); ImGui::Spacing();

    // ── Action button ──
    float bigBtnW = 460.0f;
    ImGui::SetCursorPosX((CARD_W - bigBtnW) * 0.5f);
    ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.15f, 0.55f, 0.90f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.20f, 0.65f, 1.00f, 1.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(12, 12));
    ImGui::SetWindowFontScale(1.1f);

    bool doAction = ImGui::Button(
        state.loginMode ? "Open  ->" : "Create  ->",
        ImVec2(bigBtnW, 46));

    ImGui::SetWindowFontScale(1.0f);
    ImGui::PopStyleVar();
    ImGui::PopStyleColor(2);

    if (doAction) {
        if (state.loginMode) {
            int id = loginProject(state.projectTitle, state.securityCode);
            if (id >= 0) {
                state.currentProjectId    = id;
                state.currentProjectTitle = state.projectTitle;
                state.currentSecurityCode = state.securityCode;
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
                    state.currentSecurityCode = state.securityCode;
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

    // ── Dead-space quote below card ──
    float quoteY = cardY + CARD_H + 32.0f;
    if (quoteY + 80.0f < H) {
        ImGui::SetNextWindowSize(ImVec2(W, H - quoteY), ImGuiCond_Always);
        ImGui::SetNextWindowPos(ImVec2(0, quoteY), ImGuiCond_Always);
        ImGui::SetNextWindowBgAlpha(0.0f);
        ImGui::Begin("##quote", nullptr,
                     ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                     ImGuiWindowFlags_NoMove     | ImGuiWindowFlags_NoScrollbar |
                     ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoBringToFrontOnFocus);

        ImGui::Spacing(); ImGui::Spacing();
        ImGui::SetWindowFontScale(1.15f);
        CenteredText("\" Documentation is your lifeline —", ImVec4(0.55f, 0.60f, 0.75f, 0.85f));
        CenteredText("  the bridge between today's clarity and tomorrow's confusion. \"",
                     ImVec4(0.55f, 0.60f, 0.75f, 0.85f));
        ImGui::SetWindowFontScale(1.0f);
        ImGui::Spacing();
        CenteredText("Write it now. Thank yourself later.", ImVec4(0.40f, 0.50f, 0.70f, 0.65f));

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
                 ImGuiWindowFlags_NoMove     | ImGuiWindowFlags_NoBringToFrontOnFocus);

    // ── Sidebar ──
    ImGui::BeginChild("##sidebar", ImVec2(210, 0), true);

    ImGui::SetWindowFontScale(1.2f);
    ImGui::TextColored(ImVec4(0.35f, 0.65f, 1.0f, 1.0f), "DocTracker");
    ImGui::SetWindowFontScale(1.0f);
    ImGui::Spacing();
    ImGui::TextDisabled("Documentation:");
    ImGui::TextWrapped("%s", state.currentProjectTitle.c_str());
    ImGui::Separator(); ImGui::Spacing();

    auto tabBtn = [&](const char* label, Tab t) {
        bool active = state.tab == t;
        if (active) ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.20f, 0.40f, 0.80f, 1.0f));
        if (ImGui::Button(label, ImVec2(-1, 38))) state.tab = t;
        if (active) ImGui::PopStyleColor();
        ImGui::Spacing();
    };
    tabBtn("Records",       Tab::DOCS);
    tabBtn("Add Record",    Tab::ADD_RECORD);
    tabBtn("Statistics",    Tab::STATS);
    tabBtn("Activity Log",  Tab::ACTIVITY);
    tabBtn("Help",          Tab::HELP);

    // ── Switch / New Documentation button ──
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();
    ImGui::TextDisabled("Switch documentation:");
    ImGui::Spacing();
    if (ImGui::Button("+ New Documentation", ImVec2(-1, 34))) {
        logActivity(state.currentProjectId, "Switched out");
        state.screen = Screen::LOGIN;
        state.loginMode = false;   // open straight to Create tab
        state.currentProjectId = -1;
        state.currentSecurityCode.clear();
        state.documents.clear();
        state.activity.clear();
        memset(state.projectTitle, 0, sizeof(state.projectTitle));
        memset(state.securityCode, 0, sizeof(state.securityCode));
        state.authError = false;
    }
    ImGui::Spacing();
    if (ImGui::Button("Open Other Docs", ImVec2(-1, 34))) {
        logActivity(state.currentProjectId, "Logged out");
        state.screen = Screen::LOGIN;
        state.loginMode = true;    // open to Login tab
        state.currentProjectId = -1;
        state.currentSecurityCode.clear();
        state.documents.clear();
        state.activity.clear();
        memset(state.projectTitle, 0, sizeof(state.projectTitle));
        memset(state.securityCode, 0, sizeof(state.securityCode));
        state.authError = false;
    }

    ImGui::SetCursorPosY(ImGui::GetWindowHeight() - 44);
    ImGui::Separator();
    if (ImGui::Button("Logout", ImVec2(-1, 32))) {
        logActivity(state.currentProjectId, "Logged out");
        state.screen = Screen::LOGIN;
        state.loginMode = true;
        state.currentProjectId = -1;
        state.currentSecurityCode.clear();
        state.documents.clear();
        state.activity.clear();
        memset(state.projectTitle, 0, sizeof(state.projectTitle));
        memset(state.securityCode, 0, sizeof(state.securityCode));
        state.authError = false;
    }
    ImGui::EndChild();
    ImGui::SameLine();

    // ── Main Content ──
    ImGui::BeginChild("##content", ImVec2(0, 0), false);

    // ── TAB: RECORDS ──
    if (state.tab == Tab::DOCS) {
        ImGui::Spacing();
        ImGui::SetWindowFontScale(1.3f);
        ImGui::TextColored(ImVec4(0.35f, 0.65f, 1.0f, 1.0f), "Records");
        ImGui::SetWindowFontScale(1.0f);
        ImGui::Separator(); ImGui::Spacing();

        ImGui::SetNextItemWidth(340);
        ImGui::InputText("  Search", state.searchBuf, sizeof(state.searchBuf));
        ImGui::SameLine();
        if (ImGui::Button("+ Add Record", ImVec2(130, 0))) {
            clearAddEdit(state);
            state.tab = Tab::ADD_RECORD;
        }
        ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();

        std::string search = state.searchBuf;
        for (auto& d : state.documents) {
            if (!search.empty() &&
                d.title.find(search) == std::string::npos &&
                d.tag.find(search)   == std::string::npos) continue;

            ImGui::PushID(d.id);

            // Record card row
            ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.14f, 0.15f, 0.20f, 1.0f));
            ImGui::BeginChild("##card", ImVec2(-1, 70), true);

            ImGui::SetWindowFontScale(1.05f);
            ImGui::TextColored(ImVec4(0.35f, 0.75f, 0.55f, 1.0f),
                "[%s]", d.tag.empty() ? "no tag" : d.tag.c_str());
            ImGui::SameLine();
            ImGui::Text("%s", d.title.c_str());
            ImGui::SetWindowFontScale(1.0f);
            ImGui::Spacing();
            ImGui::TextDisabled("Last modified: %s", d.lastModified.c_str());
            ImGui::SameLine(ImGui::GetWindowWidth() - 180);
            if (ImGui::Button("Edit", ImVec2(80, 0))) {
                clearAddEdit(state);
                strncpy(state.docTitle,   d.title.c_str(),   sizeof(state.docTitle)-1);
                strncpy(state.docContent, d.content.c_str(), sizeof(state.docContent)-1);
                strncpy(state.docTag,     d.tag.c_str(),     sizeof(state.docTag)-1);
                state.editMode  = true;
                state.editDocId = d.id;
                state.tab = Tab::ADD_RECORD;
            }
            ImGui::SameLine();
            if (ImGui::Button("Delete", ImVec2(80, 0))) {
                deleteDocument(state, d.id, d.title);
                ImGui::EndChild();
                ImGui::PopStyleColor();
                ImGui::PopID();
                break;
            }
            ImGui::EndChild();
            ImGui::PopStyleColor();
            ImGui::Spacing();
            ImGui::PopID();
        }

        if (state.documents.empty()) {
            ImGui::Spacing(); ImGui::Spacing();
            CenteredText("No records yet.", ImVec4(0.5f, 0.5f, 0.6f, 1.0f));
            CenteredText("Click  '+ Add Record'  to write your first entry.", ImVec4(0.5f, 0.5f, 0.6f, 1.0f));
        }
    }

    // ── TAB: ADD / EDIT RECORD ──
    else if (state.tab == Tab::ADD_RECORD) {
        ImGui::Spacing();
        ImGui::SetWindowFontScale(1.3f);
        ImGui::TextColored(ImVec4(0.35f, 0.65f, 1.0f, 1.0f),
            state.editMode ? "Edit Record" : "Add New Record");
        ImGui::SetWindowFontScale(1.0f);
        ImGui::Separator(); ImGui::Spacing(); ImGui::Spacing();

        ImGui::SetWindowFontScale(1.05f);
        ImGui::Text("Record Title");
        ImGui::SetWindowFontScale(1.0f);
        ImGui::SetNextItemWidth(-1);
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(10, 9));
        ImGui::InputText("##doctitle", state.docTitle, sizeof(state.docTitle));
        ImGui::PopStyleVar();

        ImGui::Spacing();
        ImGui::SetWindowFontScale(1.05f);
        ImGui::Text("Tag  (e.g. setup, api, notes)");
        ImGui::SetWindowFontScale(1.0f);
        ImGui::SetNextItemWidth(260);
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(10, 9));
        ImGui::InputText("##doctag", state.docTag, sizeof(state.docTag));
        ImGui::PopStyleVar();

        ImGui::Spacing();
        ImGui::SetWindowFontScale(1.05f);
        ImGui::Text("Content");
        ImGui::SetWindowFontScale(1.0f);

        // Multiline uses remaining height minus button row
        float contentH = ImGui::GetContentRegionAvail().y - 70.0f;
        ImGui::InputTextMultiline("##doccontent", state.docContent,
                                   sizeof(state.docContent),
                                   ImVec2(-1, contentH > 160 ? contentH : 160));
        ImGui::Spacing();

        ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.15f, 0.55f, 0.35f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.20f, 0.70f, 0.45f, 1.0f));
        if (ImGui::Button(state.editMode ? "Save Changes" : "Save Record", ImVec2(160, 40))) {
            if (strlen(state.docTitle) > 0) {
                saveDocument(state);
                loadActivity(state);
                clearAddEdit(state);
                state.tab = Tab::DOCS;
            }
        }
        ImGui::PopStyleColor(2);
        ImGui::SameLine(0, 14);
        if (ImGui::Button("Cancel", ImVec2(100, 40))) {
            clearAddEdit(state);
            state.tab = Tab::DOCS;
        }
    }

    // ── TAB: STATS ──
    else if (state.tab == Tab::STATS) {
        ImGui::Spacing();
        ImGui::SetWindowFontScale(1.3f);
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
        std::map<std::string, int> tagCount;
        for (auto& d : state.documents)
            tagCount[d.tag.empty() ? "(no tag)" : d.tag]++;
        for (auto& [tag, count] : tagCount)
            ImGui::Text("  %-24s  %d", tag.c_str(), count);
    }

    // ── TAB: ACTIVITY ──
    else if (state.tab == Tab::ACTIVITY) {
        ImGui::Spacing();
        ImGui::SetWindowFontScale(1.3f);
        ImGui::TextColored(ImVec4(0.35f, 0.65f, 1.0f, 1.0f), "Activity Log");
        ImGui::SetWindowFontScale(1.0f);
        ImGui::Separator(); ImGui::Spacing();

        for (auto& a : state.activity) {
            ImGui::TextDisabled("%s", a.timestamp.c_str());
            ImGui::SameLine(180);
            ImGui::Text("%s", a.action.c_str());
        }
        if (state.activity.empty())
            ImGui::TextDisabled("No activity yet.");
    }

    // ── TAB: HELP ──
    else if (state.tab == Tab::HELP) {
        ImGui::Spacing();
        ImGui::SetWindowFontScale(1.3f);
        ImGui::TextColored(ImVec4(0.35f, 0.65f, 1.0f, 1.0f), "Help");
        ImGui::SetWindowFontScale(1.0f);
        ImGui::Separator(); ImGui::Spacing();

        ImGui::TextWrapped("DocTracker lets you store and manage documentation sets securely. "
                           "Each documentation is protected by its own security code — "
                           "other documentations remain fully locked while you work.");
        ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();

        ImGui::BulletText("Documentation Name  =  your project name (acts as username)");
        ImGui::BulletText("Security Code       =  your password (hashed before storing)");
        ImGui::BulletText("Records are encrypted with your security code");
        ImGui::BulletText("Each documentation is independent and separately secured");
        ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();

        ImGui::BulletText("Records tab       — browse, search, view, delete records");
        ImGui::BulletText("Add Record tab    — write new records or edit existing ones");
        ImGui::BulletText("Statistics tab    — see counts and tag breakdown");
        ImGui::BulletText("Activity Log      — see what was done and when");
        ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();

        ImGui::BulletText("Use 'Open Other Docs' in the sidebar to switch to another documentation");
        ImGui::BulletText("Use '+ New Documentation' to create and jump to a fresh one");
        ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();

        ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.2f, 1.0f), "Security note:");
        ImGui::TextWrapped("This version uses XOR encryption and djb2 hashing. "
                           "For production use, replace with AES-256 (OpenSSL) "
                           "and bcrypt/SHA-256 password hashing.");
    }

    ImGui::EndChild();
    ImGui::End();
}

// ─────────────────────────────────────────────
//  MAIN
// ─────────────────────────────────────────────
int main() {
    glfwInit();
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);

    GLFWwindow* window = glfwCreateWindow(1200, 780, "DocTracker", nullptr, nullptr);
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui::StyleColorsDark();
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 330");

    // Style
    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowRounding    = 10.0f;
    style.FrameRounding     = 7.0f;
    style.GrabRounding      = 7.0f;
    style.PopupRounding     = 7.0f;
    style.ChildRounding     = 8.0f;
    style.ItemSpacing       = ImVec2(10, 10);
    style.FramePadding      = ImVec2(10, 8);
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
