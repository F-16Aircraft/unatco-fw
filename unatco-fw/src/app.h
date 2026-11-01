#pragma once
#include "common.h"
#include "ui.h"
#include "model.h"
#include "globe.h"

enum BtnId {
    B_BLOCK_APP = 1, B_UNBLOCK_APP, B_BLOCK_IP, B_UNBLOCK_IP, B_SEVER, B_SCAN, B_KILL,
    B_TOGGLE_ALL, B_ROTATE, B_CLEAR, B_LOG_FOLDER, B_VERIFY
};

struct App {
    HWND hwnd = nullptr;
    Fonts f;
    Globe globe;
    Model model;
    ListBox lproc, lconn, lalert;
    std::vector<Button> btns;
    RECT rHeader{}, rProc{}, rGlobe{}, rConn{}, rReg{}, rThreat{}, rAlert{};

    DWORD selPid = 0;
    uint64_t selConn = 0;
    bool showAll = false;
    std::vector<ConnRow> conns;

    std::string status;
    uint64_t statusUntil = 0;
    bool fwOk = false;
    std::string fwErr;

    int hoverBtn = -1, downBtn = -1;
    bool globeDrag = false;
    uint64_t lastRefresh = 0;

    HDC backDC = nullptr;
    HBITMAP backBmp = nullptr, oldBmp = nullptr;
    int bw = 0, bh = 0;
    int W = 0, H = 0;
};

extern App A;

uint64_t connKey(const Conn& c);
const ConnRow* selectedConn();
void setStatus(const std::string& s, uint64_t ms = 6000);
void layoutAll(int W, int H);
void refreshModel();
void paintAll(HDC wdc);
void onAction(int id);
void onSelectProc(DWORD pid);
void onSelectConn(uint64_t key);
