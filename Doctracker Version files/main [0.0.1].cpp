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
//  Simple XOR "encryption" for stored content
//  Replace with AES (OpenSSL) for real security
// ─────────────────────────────────────────────
std::string xorEncrypt(const std::string& data, const std::string& key) {
    std::string result = data;
    for (size_t i = 0; i < data.size(); i++)
        result[i] = data[i] ^ key[i % key.size()];
    return result;
}
std::string xorDecrypt(const std::string& data, const std::string& key) {
    return xorEncrypt(data, key); // XOR is symmetric
}

// ─────────────────────────────────────────────
//  Simple hash (djb2) for passwords
//  Replace with bcrypt or SHA-256 for production
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
    std::string content;   // decrypted at runtime
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
enum class Tab    { DOCS, ADD_EDIT, STATS, ACTIVITY, HELP };

struct AppState {
    Screen screen = Screen::LOGIN;
    Tab    tab    = Tab::DOCS;

    // login fields
    char projectTitle[128] = {};
    char securityCode[128] = {};
    bool authError = false;

    // session
    int  currentProjectId = -1;
    std::string currentProjectTitle;
    std::string currentSecurityCode; // kept in memory for encrypt/decrypt

    // documents
    std::vector<Document> documents;
    char searchBuf[128] = {};

    // add/edit
    bool editMode = false;
    int  editDocId = -1;
    char docTitle[256]   = {};
    char docContent[4096]= {};
    char docTag[64]      = {};

    // activity
    std::vector<ActivityEntry> activity;

    // stats
    int totalDocs    = 0;
    int taggedDocs   = 0;
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
        "  id           INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  project_id   INTEGER NOT NULL,"
        "  title        TEXT NOT NULL,"
        "  content      TEXT NOT NULL,"
        "  tag          TEXT,"
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

// returns project id or -1 if not found / wrong password
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

    // decrypt content
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
    state.totalDocs  = (int)state.documents.size();
    state.taggedDocs = 0;
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
        logActivity(state.currentProjectId, "Edited doc: " + title);
    } else {
        std::string sql = "INSERT INTO documents (project_id, title, content, tag, last_modified) VALUES ("
                        + std::to_string(state.currentProjectId) + ", '"
                        + title + "', '" + content + "', '" + tag + "', '" + ts + "');";
        sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr);
        logActivity(state.currentProjectId, "Added doc: " + title);
    }
    loadDocuments(state);
    computeStats(state);
}

void deleteDocument(AppState& state, int docId, const std::string& docTitle) {
    std::string sql = "DELETE FROM documents WHERE id=" + std::to_string(docId) + ";";
    sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr);
    logActivity(state.currentProjectId, "Deleted doc: " + docTitle);
    loadDocuments(state);
    computeStats(state);
}

// ─────────────────────────────────────────────
//  UI helpers
// ─────────────────────────────────────────────
void clearAddEdit(AppState& state) {
    state.editMode  = false;
    state.editDocId = -1;
    memset(state.docTitle,   0, sizeof(state.docTitle));
    memset(state.docContent, 0, sizeof(state.docContent));
    memset(state.docTag,     0, sizeof(state.docTag));
}

// ─────────────────────────────────────────────
//  SCREENS
// ─────────────────────────────────────────────
void renderLogin(AppState& state) {
    ImGui::SetNextWindowSize(ImVec2(440, 300), ImGuiCond_Always);
    ImGui::SetNextWindowPos(ImVec2(ImGui::GetIO().DisplaySize.x * 0.5f,
                                   ImGui::GetIO().DisplaySize.y * 0.5f),
                             ImGuiCond_Always, ImVec2(0.5f, 0.5f));
    ImGui::Begin("##login", nullptr,
                 ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                 ImGuiWindowFlags_NoMove     | ImGuiWindowFlags_NoScrollbar);

    ImGui::Spacing();
    ImGui::SetCursorPosX((440 - ImGui::CalcTextSize("DocTracker").x) * 0.5f);
    ImGui::TextColored(ImVec4(0.3f, 0.6f, 1.0f, 1.0f), "DocTracker");
    ImGui::SetCursorPosX((440 - ImGui::CalcTextSize("Project Documentation Manager").x) * 0.5f);
    ImGui::TextDisabled("Project Documentation Manager");
    ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();

    ImGui::Text("Project Title");
    ImGui::SetNextItemWidth(-1);
    ImGui::InputText("##title", state.projectTitle, sizeof(state.projectTitle));
    ImGui::Spacing();
    ImGui::Text("Security Code");
    ImGui::SetNextItemWidth(-1);
    ImGui::InputText("##code", state.securityCode, sizeof(state.securityCode),
                     ImGuiInputTextFlags_Password);
    ImGui::Spacing();

    if (state.authError) {
        ImGui::TextColored(ImVec4(1,0.3f,0.3f,1), "Invalid title or security code.");
        ImGui::Spacing();
    }

    float btnW = 190;
    float totalW = btnW * 2 + 10;
    ImGui::SetCursorPosX((440 - totalW) * 0.5f);

    if (ImGui::Button("Login", ImVec2(btnW, 36))) {
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
            logActivity(id, "Logged in");
        } else {
            state.authError = true;
        }
    }
    ImGui::SameLine(0, 10);
    if (ImGui::Button("Create Project", ImVec2(btnW, 36))) {
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
                logActivity(id, "Created project");
            }
        }
    }
    ImGui::End();
}

void renderDashboard(AppState& state) {
    ImGuiIO& io = ImGui::GetIO();
    ImGui::SetNextWindowSize(io.DisplaySize, ImGuiCond_Always);
    ImGui::SetNextWindowPos(ImVec2(0,0), ImGuiCond_Always);
    ImGui::Begin("##dashboard", nullptr,
                 ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                 ImGuiWindowFlags_NoMove     | ImGuiWindowFlags_NoBringToFrontOnFocus);

    // ── Sidebar ──
    ImGui::BeginChild("##sidebar", ImVec2(200, 0), true);
    ImGui::TextColored(ImVec4(0.3f,0.6f,1.0f,1.0f), "DocTracker");
    ImGui::TextDisabled("%s", state.currentProjectTitle.c_str());
    ImGui::Separator(); ImGui::Spacing();

    auto tabBtn = [&](const char* label, Tab t) {
        bool active = state.tab == t;
        if (active) ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.2f,0.4f,0.8f,1.0f));
        if (ImGui::Button(label, ImVec2(-1, 36))) state.tab = t;
        if (active) ImGui::PopStyleColor();
        ImGui::Spacing();
    };
    tabBtn("Documents",    Tab::DOCS);
    tabBtn("Add / Edit",   Tab::ADD_EDIT);
    tabBtn("Statistics",   Tab::STATS);
    tabBtn("Activity Log", Tab::ACTIVITY);
    tabBtn("Help",         Tab::HELP);

    ImGui::SetCursorPosY(ImGui::GetWindowHeight() - 44);
    ImGui::Separator();
    if (ImGui::Button("Logout", ImVec2(-1, 32))) {
        logActivity(state.currentProjectId, "Logged out");
        state.screen = Screen::LOGIN;
        state.currentProjectId = -1;
        state.currentSecurityCode.clear();
        state.documents.clear();
        state.activity.clear();
        memset(state.projectTitle, 0, sizeof(state.projectTitle));
        memset(state.securityCode, 0, sizeof(state.securityCode));
    }
    ImGui::EndChild();
    ImGui::SameLine();

    // ── Main Content ──
    ImGui::BeginChild("##content", ImVec2(0, 0), false);

    // ── TAB: DOCS ──
    if (state.tab == Tab::DOCS) {
        ImGui::Text("Documents"); ImGui::Separator(); ImGui::Spacing();
        ImGui::SetNextItemWidth(300);
        ImGui::InputText("Search", state.searchBuf, sizeof(state.searchBuf));
        ImGui::Spacing();

        std::string search = state.searchBuf;
        for (auto& d : state.documents) {
            if (!search.empty() &&
                d.title.find(search) == std::string::npos &&
                d.tag.find(search)   == std::string::npos) continue;

            ImGui::PushID(d.id);
            ImGui::TextColored(ImVec4(0.3f,0.8f,0.6f,1.0f), "[%s]", d.tag.empty() ? "no tag" : d.tag.c_str());
            ImGui::SameLine();
            ImGui::Text("%s", d.title.c_str());
            ImGui::SameLine();
            ImGui::TextDisabled("  %s", d.lastModified.c_str());

            if (ImGui::Button("View")) {
                clearAddEdit(state);
                strncpy(state.docTitle,   d.title.c_str(),   sizeof(state.docTitle)-1);
                strncpy(state.docContent, d.content.c_str(), sizeof(state.docContent)-1);
                strncpy(state.docTag,     d.tag.c_str(),     sizeof(state.docTag)-1);
                state.editMode  = true;
                state.editDocId = d.id;
                state.tab = Tab::ADD_EDIT;
            }
            ImGui::SameLine();
            if (ImGui::Button("Delete")) {
                deleteDocument(state, d.id, d.title);
                ImGui::PopID();
                break;
            }
            ImGui::Separator();
            ImGui::PopID();
        }
        if (state.documents.empty())
            ImGui::TextDisabled("No documents yet. Go to Add / Edit to create one.");

        ImGui::Spacing();
        if (ImGui::Button("+ New Document", ImVec2(160, 32))) {
            clearAddEdit(state);
            state.tab = Tab::ADD_EDIT;
        }
    }

    // ── TAB: ADD / EDIT ──
    else if (state.tab == Tab::ADD_EDIT) {
        ImGui::Text(state.editMode ? "Edit Document" : "New Document");
        ImGui::Separator(); ImGui::Spacing();

        ImGui::Text("Title");
        ImGui::SetNextItemWidth(-1);
        ImGui::InputText("##doctitle", state.docTitle, sizeof(state.docTitle));
        ImGui::Spacing();

        ImGui::Text("Tag  (e.g. setup, api, notes)");
        ImGui::SetNextItemWidth(200);
        ImGui::InputText("##doctag", state.docTag, sizeof(state.docTag));
        ImGui::Spacing();

        ImGui::Text("Content");
        ImGui::InputTextMultiline("##doccontent", state.docContent,
                                   sizeof(state.docContent), ImVec2(-1, 300));
        ImGui::Spacing();

        if (ImGui::Button(state.editMode ? "Save Changes" : "Save Document", ImVec2(160, 36))) {
            if (strlen(state.docTitle) > 0) {
                saveDocument(state);
                loadActivity(state);
                clearAddEdit(state);
                state.tab = Tab::DOCS;
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(100, 36))) {
            clearAddEdit(state);
            state.tab = Tab::DOCS;
        }
    }

    // ── TAB: STATS ──
    else if (state.tab == Tab::STATS) {
        ImGui::Text("Statistics"); ImGui::Separator(); ImGui::Spacing();
        ImGui::Text("Project       : %s", state.currentProjectTitle.c_str());
        ImGui::Spacing();
        ImGui::Text("Total Docs    : %d", state.totalDocs);
        ImGui::Text("Tagged Docs   : %d", state.taggedDocs);
        ImGui::Text("Untagged Docs : %d", state.totalDocs - state.taggedDocs);
        ImGui::Spacing();
        if (!state.lastModified.empty())
            ImGui::Text("Last Modified : %s", state.lastModified.c_str());

        ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
        ImGui::TextDisabled("Tags breakdown:");
        std::map<std::string,int> tagCount;
        for (auto& d : state.documents)
            tagCount[d.tag.empty() ? "(no tag)" : d.tag]++;
        for (auto& [tag, count] : tagCount)
            ImGui::Text("  %-20s  %d", tag.c_str(), count);
    }

    // ── TAB: ACTIVITY ──
    else if (state.tab == Tab::ACTIVITY) {
        ImGui::Text("Activity Log"); ImGui::Separator(); ImGui::Spacing();
        for (auto& a : state.activity) {
            ImGui::TextDisabled("%s", a.timestamp.c_str());
            ImGui::SameLine(160);
            ImGui::Text("%s", a.action.c_str());
        }
        if (state.activity.empty())
            ImGui::TextDisabled("No activity yet.");
    }

    // ── TAB: HELP ──
    else if (state.tab == Tab::HELP) {
        ImGui::Text("Help"); ImGui::Separator(); ImGui::Spacing();
        ImGui::TextWrapped("DocTracker lets you store and manage project documentation securely.");
        ImGui::Spacing();
        ImGui::BulletText("Project Title = your project name (acts as username)");
        ImGui::BulletText("Security Code = your password (hashed before storing)");
        ImGui::BulletText("Content is encrypted with your security code");
        ImGui::BulletText("Even if someone finds doctracker.db, they cannot read your docs");
        ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
        ImGui::BulletText("Documents tab  — browse, search, view, delete docs");
        ImGui::BulletText("Add / Edit tab — write new docs or edit existing ones");
        ImGui::BulletText("Statistics tab — see counts and tag breakdown");
        ImGui::BulletText("Activity Log   — see what was done and when");
        ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
        ImGui::TextColored(ImVec4(1,0.8f,0.2f,1), "Security note:");
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

    GLFWwindow* window = glfwCreateWindow(1100, 700, "DocTracker", nullptr, nullptr);
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui::StyleColorsDark();
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 330");

    // style tweaks
    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowRounding   = 8.0f;
    style.FrameRounding    = 6.0f;
    style.GrabRounding     = 6.0f;
    style.ItemSpacing      = ImVec2(8, 8);
    style.FramePadding     = ImVec2(8, 6);
    style.Colors[ImGuiCol_WindowBg]  = ImVec4(0.10f, 0.10f, 0.13f, 1.0f);
    style.Colors[ImGuiCol_ChildBg]   = ImVec4(0.12f, 0.12f, 0.16f, 1.0f);
    style.Colors[ImGuiCol_Button]    = ImVec4(0.18f, 0.22f, 0.35f, 1.0f);
    style.Colors[ImGuiCol_ButtonHovered] = ImVec4(0.25f,0.35f,0.60f,1.0f);
    style.Colors[ImGuiCol_FrameBg]   = ImVec4(0.16f, 0.16f, 0.20f, 1.0f);
    style.Colors[ImGuiCol_Header]    = ImVec4(0.20f, 0.30f, 0.55f, 1.0f);
    style.Colors[ImGuiCol_Separator] = ImVec4(0.25f, 0.25f, 0.35f, 1.0f);

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
        glClearColor(0.10f, 0.10f, 0.13f, 1.0f);
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
