#pragma once
#include <string>
#include <cstdint>
#include <cmath>

// Hand-authored geography: country centroids (for placing registry-reported countries on the
// globe) and coarse continent outlines. Approximate by design - this is a HUD, not a map.
namespace geo {
struct Country { const char* cc; const char* name; float lat, lon; };
const Country* findCountry(const std::string& cc);   // nullptr if unknown

struct Poly { const float* ll; int n; bool water; };  // ll = lat,lon,lat,lon...
int polyCount();
Poly poly(int i);

// 1-degree land raster built once from the outlines (even-odd fill, water polygons carve out).
void buildMask();
bool isLand(double latDeg, double lonDeg);
}  // namespace geo
