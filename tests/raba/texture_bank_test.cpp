/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */
#include <cmath>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <string>

#include "TextureBank.h"

using aidl::android::hardware::vibrator::TextureBank;

static int sFailed;

static void check(const char* name, bool ok) {
    printf("%s %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) sFailed++;
}

static std::vector<int8_t> readS8(const char* path) {
    std::ifstream in(path, std::ios::binary);
    std::vector<char> d((std::istreambuf_iterator<char>(in)), {});
    return std::vector<int8_t>(d.begin(), d.end());
}

int main(int argc, char** argv) {
    if (argc < 2) return 2;
    std::ifstream in(argv[1], std::ios::binary);
    std::vector<uint8_t> file((std::istreambuf_iterator<char>(in)), {});

    TextureBank bank = TextureBank::parse(file);
    check("onyx bank: 11 waves", bank.count() == 11);
    // parse_ram.py: 14.5, 18.9, 17.6, 15.8, 15.8, 17.5, 12.5, 12.3, 20.2, 17.8, 5.8 ms.
    const int ms[] = {15, 19, 18, 16, 16, 18, 13, 13, 21, 18, 6};
    bool durations = true;
    for (int w = 1; w <= bank.count() && w <= 11; w++) durations &= bank.durationMs(w) == ms[w - 1];
    check("durations", durations);
    check("wave 5 is wave 4", bank.has(5) && bank.wave(4) == bank.wave(5));
    float peak = 0, peak11 = 0;
    for (int w = 1; w <= bank.count(); w++)
        for (float x : bank.wave(w)) peak = std::max(peak, std::fabs(x));
    for (float x : bank.wave(11)) peak11 = std::max(peak11, std::fabs(x));
    check("full scale", peak > 0.99f && peak <= 1.0f + 1e-6f);
    check("wave 11 is quiet", peak11 > 0.3f && peak11 < 0.4f);
    check("no wave 0 or 12", !bank.has(0) && !bank.has(12) && bank.durationMs(12) == 0);

    // Boost: what was benched (lab/haptics/raba/waves, made by make_boost_waves.py) is what plays.
    constexpr float kF0 = 169.9f;
    check("boost 0 is the wave", TextureBank::boosted(bank.wave(6), 0, kF0) == bank.wave(6));
    check("boost too small for a cycle is the wave", TextureBank::boosted(bank.wave(6), .1f, kF0) == bank.wave(6));
    check("no zero crossing: the wave", TextureBank::boosted(bank.wave(11), 1, kF0) == bank.wave(11));
    bool inScale = true;
    for (int w = 1; w <= bank.count(); w++) {
        for (float b : {0.25f, 0.5f, 1.f}) {
            for (float x : TextureBank::boosted(bank.wave(w), b, kF0)) inScale &= std::fabs(x) <= 1.f;
        }
    }
    check("boost stays in full scale", inScale);
    const auto b1 = TextureBank::boosted(bank.wave(6), 1.f, kF0), b05 = TextureBank::boosted(bank.wave(6), .5f, kF0);
    check("boost lengthens", b05.size() > bank.wave(6).size() && b1.size() > b05.size());
    check("boost ends at rest", std::fabs(b1.back()) < 0.05f && std::fabs(b05.back()) < 0.05f);
    // Clipping is what crackled: a clean body has only sine crests near full scale.
    int flat = 0;
    for (size_t i = 1; i < b1.size(); i++) flat += std::fabs(b1[i]) >= 0.999f && b1[i] == b1[i - 1];
    check("boost never clips", flat == 0);
    if (argc > 2) {
        for (int w : {6, 8, 10}) {
            for (auto [b, name] : {std::pair{1.f, "-L100"}, std::pair{.5f, "-L80-b50"}}) {
                const std::string path = std::string(argv[2]) + "/w" + std::to_string(w) + name + ".s8";
                const std::vector<int8_t> bench = readS8(path.c_str());
                const auto y = TextureBank::boosted(bank.wave(w), b, kF0);
                int off = 0;
                for (size_t i = 0; i < std::min(y.size(), bench.size()); i++) {
                    off += std::abs(std::lround(y[i] * 127) - bench[i]) > 1;
                }
                check(("boost matches the benched w" + std::to_string(w) + name).c_str(),
                      !bench.empty() && y.size() == bench.size() && off == 0);
            }
        }
    }

    check("empty", TextureBank::parse({}).count() == 0);
    std::vector<uint8_t> bad = file;
    bad[4] = 0;
    check("no base mark", TextureBank::parse(bad).count() == 0);
    std::vector<uint8_t> cut(file.begin(), file.begin() + file.size() / 2);
    TextureBank half = TextureBank::parse(cut);
    check("truncated: only whole waves", half.count() > 0 && half.count() < 11);
    std::vector<uint8_t> noise(4096);
    for (size_t i = 0; i < noise.size(); i++) noise[i] = static_cast<uint8_t>(i * 131 + 7);
    noise[4] = 0x55;
    check("noise: no crash", TextureBank::parse(noise).count() >= 0);
    std::vector<uint8_t> tableOnly(file.begin(), file.begin() + 9);
    check("header only", TextureBank::parse(tableOnly).count() == 0);

    if (sFailed) {
        printf("%d failed\n", sFailed);
        return 1;
    }
    printf("all passed\n");
    return 0;
}
