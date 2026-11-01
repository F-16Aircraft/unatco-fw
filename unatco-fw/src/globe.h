#pragma once
#include "common.h"

// Software-rendered orthographic globe (GDI + a DIB section; no OpenGL, no libraries).
struct GlobeTarget {
    IpAddr ip;
    double lat = 0, lon = 0;
    std::string cc;          // country code ("" = unresolved, drawn nowhere)
    std::string country;     // display name
    COLORREF color = RGB(80, 220, 230);
    bool highlight = false;  // belongs to the selected process
    bool blocked = false;
};

struct GlobeHome {
    bool valid = false;
    double lat = 0, lon = 0;
    std::string label;
};

class Globe {
public:
    Globe();
    ~Globe();
    void setHome(const GlobeHome& h);
    void setTargets(const std::vector<GlobeTarget>& t);
    void render(HDC dst, int x, int y, int w, int h, HFONT font, HFONT bigFont, double seconds);
    void mouseDown(int x, int y);
    void mouseMove(int x, int y);
    void mouseUp();
    bool dragging() const { return drag_; }
    void centerOn(double lat, double lon);       // eases the view toward a point
    void setAutoRotate(bool on) { auto_ = on; }
    bool autoRotate() const { return auto_; }

private:
    void ensure(int w, int h);
    void project(double lat, double lon, double r, double& x, double& y, double& z) const;
    void projectVec(double vx, double vy, double vz, double& x, double& y, double& z) const;

    HDC mem_ = nullptr;
    HBITMAP bmp_ = nullptr, oldBmp_ = nullptr;
    uint32_t* px_ = nullptr;
    int bw_ = 0, bh_ = 0;

    GlobeHome home_;
    std::vector<GlobeTarget> targets_;
    double lam0_ = -40, phi0_ = 22;               // degrees, view centre
    double goalLam_ = 0, goalPhi_ = 0;
    bool easing_ = false, auto_ = true, drag_ = false;
    int lx_ = 0, ly_ = 0;
    double lastT_ = 0;
    double cx_ = 0, cy_ = 0, R_ = 1;
};
