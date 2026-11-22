/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 *
 * Host build tool (`pantau_atlas_bake`): rasterizes Google Sans Flex at 4 exact HUD sizes
 * (26px label, 30px value, 54px big FPS, 20px micro top-docked bar) plus 3 monochrome Material You
 * SDF icons (kernel chip, system daemon terminal, thread split) into `/system_ext/etc/pantau/atlas.bin`
 * (magic "PNA1" v2), mapped PROT_READ MAP_SHARED by pantaud.
 * Zero FreeType/Skia/HarfBuzz needed at runtime.
 */

#include <ft2build.h>
#include FT_FREETYPE_H

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace {

constexpr uint32_t kAtlasMagic = 0x31414E50u; // "PNA1"
constexpr uint16_t kAtlasVersion = 2;
constexpr uint16_t kStyleCount = 4;

// Style 0 = label (26px), Style 1 = metric value (30px), Style 2 = big FPS (54px),
// Style 3 = micro top-docked Mini bar (20px)
constexpr uint32_t kStylePx[kStyleCount] = {26, 30, 54, 20};

// ASCII 32..=126 (95) + 8 symbols + 3 monochrome icons = 106 slots per style.
// Monochrome icons are baked only in Style 0 (empty 0x0 bitmaps in other styles to save space).
constexpr uint32_t kExtraCodepoints[] = {
        0x00B0, // 95: ° degree
        0x00B7, // 96: · middle dot
        0x2014, // 97: — em dash
        0x2193, // 98: ↓ down arrow (RX)
        0x2191, // 99: ↑ up arrow (TX)
        0x00D7, // 100: × multiply
        0x2026, // 101: … ellipsis
        0x00B1, // 102: ± plus-minus (RTT jitter)
};
constexpr uint32_t kAsciiStart = 32;
constexpr uint32_t kAsciiCount = 95;
constexpr uint32_t kExtraCount = sizeof(kExtraCodepoints) / sizeof(kExtraCodepoints[0]);
constexpr uint32_t kIconCount = 3; // 103=kernel chip, 104=daemon terminal, 105=thread split
constexpr uint32_t kGlyphsPerStyle = kAsciiCount + kExtraCount + kIconCount; // 106
constexpr uint32_t kIconDim = 24;

struct __attribute__((packed)) AtlasHeader {
    uint32_t magic;
    uint16_t version;
    uint16_t style_count;
    uint32_t glyphs_per_style;
    uint32_t glyph_count;
    uint32_t bitmap_offset;
    uint32_t bitmap_size;
    uint16_t line_heights[kStyleCount];
    uint16_t ascents[kStyleCount];
};

struct __attribute__((packed)) GlyphMetric {
    uint32_t codepoint;
    uint32_t bitmap_off;
    uint16_t w;
    uint16_t h;
    int16_t  bearing_x;
    int16_t  bearing_y;
    uint16_t advance_x;
    uint8_t  style;
    uint8_t  _pad;
};

static_assert(sizeof(AtlasHeader) == 40, "AtlasHeader size mismatch");
static_assert(sizeof(GlyphMetric) == 20, "GlyphMetric size mismatch");

float sdRoundedBox(float px, float py, float cx, float cy, float bx, float by, float r) {
    float qx = std::fabs(px - cx) - bx + r;
    float qy = std::fabs(py - cy) - by + r;
    float ox = std::max(qx, 0.0f);
    float oy = std::max(qy, 0.0f);
    return std::min(std::max(qx, qy), 0.0f) + std::sqrt(ox * ox + oy * oy) - r;
}

float sdSegment(float px, float py, float ax, float ay, float bx, float by) {
    float pax = px - ax, pay = py - ay;
    float bax = bx - ax, bay = by - ay;
    float denom = bax * bax + bay * bay;
    float h = denom > 1e-6f ? std::clamp((pax * bax + pay * bay) / denom, 0.0f, 1.0f) : 0.0f;
    float dx = pax - bax * h;
    float dy = pay - bay * h;
    return std::sqrt(dx * dx + dy * dy);
}

// Rasterizes 24x24 anti-aliased monochrome Material You vector icon (alpha8).
void bakeMonochromeIcon(uint32_t iconIdx, std::vector<uint8_t>& out) {
    for (uint32_t y = 0; y < kIconDim; ++y) {
        for (uint32_t x = 0; x < kIconDim; ++x) {
            float px = static_cast<float>(x) + 0.5f;
            float py = static_cast<float>(y) + 0.5f;
            float d = 1e9f;

            if (iconIdx == 0) {
                // Kernel chip icon: rounded center square + inner core + 8 pins.
                float outer = std::fabs(sdRoundedBox(px, py, 12.0f, 12.0f, 5.2f, 5.2f, 1.8f)) - 0.9f;
                float core = sdRoundedBox(px, py, 12.0f, 12.0f, 2.0f, 2.0f, 0.6f);
                d = std::min(outer, core);
                const float pins[2] = {9.2f, 14.8f};
                for (float p : pins) {
                    d = std::min(d, sdSegment(px, py, p, 3.0f, p, 6.2f) - 0.85f);
                    d = std::min(d, sdSegment(px, py, p, 17.8f, p, 21.0f) - 0.85f);
                    d = std::min(d, sdSegment(px, py, 3.0f, p, 6.2f, p) - 0.85f);
                    d = std::min(d, sdSegment(px, py, 17.8f, p, 21.0f, p) - 0.85f);
                }
            } else if (iconIdx == 1) {
                // System daemon terminal icon: rounded frame + `>_` prompt.
                float frame = std::fabs(sdRoundedBox(px, py, 12.0f, 12.0f, 8.2f, 7.2f, 2.6f)) - 0.9f;
                float chev1 = sdSegment(px, py, 7.0f, 9.0f, 10.6f, 12.0f) - 0.95f;
                float chev2 = sdSegment(px, py, 10.6f, 12.0f, 7.0f, 15.0f) - 0.95f;
                float bar = sdSegment(px, py, 12.6f, 15.0f, 17.0f, 15.0f) - 0.95f;
                d = std::min({frame, chev1, chev2, bar});
            } else {
                // Thread split icon: fork/branching arrows with 3 dots.
                float stem = sdSegment(px, py, 5.0f, 12.0f, 11.5f, 12.0f) - 0.95f;
                float up = sdSegment(px, py, 11.5f, 12.0f, 17.5f, 7.2f) - 0.95f;
                float dn = sdSegment(px, py, 11.5f, 12.0f, 17.5f, 16.8f) - 0.95f;
                float c0 = std::hypot(px - 5.0f, py - 12.0f) - 2.1f;
                float c1 = std::hypot(px - 18.2f, py - 7.0f) - 2.1f;
                float c2 = std::hypot(px - 18.2f, py - 17.0f) - 2.1f;
                d = std::min({stem, up, dn, c0, c1, c2});
            }

            float cov = std::clamp(0.5f - d, 0.0f, 1.0f);
            out.push_back(static_cast<uint8_t>(std::lround(cov * 255.0f)));
        }
    }
}

// Rasterizes a crisp anti-aliased SDF vertical arrow (`↓` / `↑`) sized to match `px` font height.
// GoogleSansFlex omits U+2191/U+2193, so baking them analytically prevents `.notdef` tofu boxes.
void bakeArrowGlyph(bool down, uint32_t px, GlyphMetric& m, std::vector<uint8_t>& out) {
    const uint32_t h = std::max(10u, (px * 72u + 50u) / 100u);
    const uint32_t w = std::max(8u, (h * 68u + 50u) / 100u);
    const float cx = static_cast<float>(w) * 0.5f;
    const float stroke = std::max(0.75f, static_cast<float>(px) * 0.048f);
    const float top_y = 1.4f;
    const float bot_y = static_cast<float>(h) - 1.4f;
    const float head = std::max(2.6f, static_cast<float>(w) * 0.36f);
    const float tip_y = down ? bot_y : top_y;
    const float wing_y = down ? (bot_y - head) : (top_y + head);

    m.w = static_cast<uint16_t>(w);
    m.h = static_cast<uint16_t>(h);
    m.bearing_x = 1;
    m.bearing_y = static_cast<int16_t>(h);
    m.advance_x = static_cast<uint16_t>(w + 2);
    m.bitmap_off = static_cast<uint32_t>(out.size());

    for (uint32_t y = 0; y < h; ++y) {
        const float py = static_cast<float>(y) + 0.5f;
        for (uint32_t x = 0; x < w; ++x) {
            const float px_f = static_cast<float>(x) + 0.5f;
            float d = sdSegment(px_f, py, cx, top_y, cx, bot_y) - stroke;
            d = std::min(d, sdSegment(px_f, py, cx, tip_y, cx - head, wing_y) - stroke);
            d = std::min(d, sdSegment(px_f, py, cx, tip_y, cx + head, wing_y) - stroke);
            float cov = std::clamp(0.5f - d, 0.0f, 1.0f);
            out.push_back(static_cast<uint8_t>(std::lround(cov * 255.0f)));
        }
    }
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 3) {
        std::fprintf(stderr, "Usage: %s <input.ttf> <output.bin>\n", argv[0]);
        return 2;
    }

    FT_Library ft = nullptr;
    if (FT_Init_FreeType(&ft) != 0) {
        std::fprintf(stderr, "FT_Init_FreeType failed\n");
        return 1;
    }

    FT_Face face = nullptr;
    if (FT_New_Face(ft, argv[1], 0, &face) != 0) {
        std::fprintf(stderr, "FT_New_Face failed for %s\n", argv[1]);
        FT_Done_FreeType(ft);
        return 1;
    }

    AtlasHeader hdr{};
    hdr.magic = kAtlasMagic;
    hdr.version = kAtlasVersion;
    hdr.style_count = kStyleCount;
    hdr.glyphs_per_style = kGlyphsPerStyle;
    hdr.glyph_count = kStyleCount * kGlyphsPerStyle;

    std::vector<GlyphMetric> metrics(hdr.glyph_count);
    std::vector<uint8_t> bitmaps;
    bitmaps.reserve(96 * 1024);

    for (uint16_t s = 0; s < kStyleCount; ++s) {
        if (FT_Set_Pixel_Sizes(face, 0, kStylePx[s]) != 0) {
            std::fprintf(stderr, "FT_Set_Pixel_Sizes(%u) failed\n", kStylePx[s]);
            FT_Done_Face(face);
            FT_Done_FreeType(ft);
            return 1;
        }
        hdr.line_heights[s] = static_cast<uint16_t>((face->size->metrics.height + 32) >> 6);
        hdr.ascents[s] = static_cast<uint16_t>((face->size->metrics.ascender + 32) >> 6);
        if (hdr.line_heights[s] == 0) hdr.line_heights[s] = static_cast<uint16_t>(kStylePx[s] + 4);
        if (hdr.ascents[s] == 0) hdr.ascents[s] = static_cast<uint16_t>(kStylePx[s]);

        for (uint32_t i = 0; i < kGlyphsPerStyle; ++i) {
            uint32_t out_idx = static_cast<uint32_t>(s) * kGlyphsPerStyle + i;
            GlyphMetric& m = metrics[out_idx];
            m.style = static_cast<uint8_t>(s);
            m._pad = 0;

            if (i >= kAsciiCount + kExtraCount) {
                uint32_t iconIdx = i - (kAsciiCount + kExtraCount);
                m.codepoint = 0xE000u + iconIdx;
                if (s == 0) {
                    m.w = kIconDim;
                    m.h = kIconDim;
                    m.bearing_x = 0;
                    m.bearing_y = static_cast<int16_t>(kIconDim - 3);
                    m.advance_x = kIconDim + 4;
                    m.bitmap_off = static_cast<uint32_t>(bitmaps.size());
                    bakeMonochromeIcon(iconIdx, bitmaps);
                }
                continue;
            }

            uint32_t cp = (i < kAsciiCount) ? (kAsciiStart + i) : kExtraCodepoints[i - kAsciiCount];
            m.codepoint = cp;

            if (cp == 0x2193u || cp == 0x2191u) {
                bakeArrowGlyph(cp == 0x2193u, kStylePx[s], m, bitmaps);
                continue;
            }

            if (FT_Load_Char(face, cp, FT_LOAD_RENDER | FT_LOAD_TARGET_NORMAL) != 0) {
                m.advance_x = static_cast<uint16_t>(kStylePx[s] / 2);
                continue;
            }
            const FT_GlyphSlot g = face->glyph;
            const FT_Bitmap& bm = g->bitmap;

            m.w = static_cast<uint16_t>(bm.width);
            m.h = static_cast<uint16_t>(bm.rows);
            m.bearing_x = static_cast<int16_t>(g->bitmap_left);
            m.bearing_y = static_cast<int16_t>(g->bitmap_top);
            m.advance_x = static_cast<uint16_t>((g->advance.x + 32) >> 6);
            m.bitmap_off = static_cast<uint32_t>(bitmaps.size());

            const int pitch = bm.pitch >= 0 ? bm.pitch : -bm.pitch;
            for (unsigned row = 0; row < bm.rows; ++row) {
                const uint8_t* src = bm.buffer + row * pitch;
                bitmaps.insert(bitmaps.end(), src, src + bm.width);
            }
        }
    }

    hdr.bitmap_offset =
            static_cast<uint32_t>(sizeof(AtlasHeader) + metrics.size() * sizeof(GlyphMetric));
    hdr.bitmap_size = static_cast<uint32_t>(bitmaps.size());

    FILE* fp = std::fopen(argv[2], "wb");
    if (!fp) {
        std::fprintf(stderr, "Failed to open output %s\n", argv[2]);
        FT_Done_Face(face);
        FT_Done_FreeType(ft);
        return 1;
    }
    bool ok = std::fwrite(&hdr, sizeof(hdr), 1, fp) == 1 &&
              std::fwrite(metrics.data(), sizeof(GlyphMetric), metrics.size(), fp) ==
                      metrics.size() &&
              (bitmaps.empty() || std::fwrite(bitmaps.data(), 1, bitmaps.size(), fp) == bitmaps.size());
    std::fclose(fp);
    FT_Done_Face(face);
    FT_Done_FreeType(ft);

    if (!ok) {
        std::fprintf(stderr, "Write failed for %s\n", argv[2]);
        return 1;
    }
    return 0;
}
