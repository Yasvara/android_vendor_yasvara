// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

// Plays one synthetic waveform through the sih688x stream device and measures it
// with the phone's own accelerometer. One CSV line per trial on stdout.
//
// Besides plain waves it plays game patterns: gunfire (a kick and a decay per round) and
// `follow`, the HAL's follow loop (StreamPlayer::runFollow) rendering a game-like envelope, so
// each part of the 4D game path can be felt and measured on its own.

#include <android/looper.h>
#include <android/sensor.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {

// haptic_misc.h / haptic.h
constexpr unsigned kIoctlGroup = 0x52;
constexpr unsigned long kIoctlSetGain = _IO(kIoctlGroup, 0x05);
constexpr unsigned long kIoctlStream = _IO(kIoctlGroup, 0x0A);
constexpr unsigned long kIoctlGetF0 = _IO(kIoctlGroup, 0x11);
constexpr unsigned long kIoctlStop = _IO(kIoctlGroup, 0x12);
constexpr uint8_t kBufValid = 0x55;
constexpr int kBufCount = 16;
constexpr int kBufData = 1000;

#pragma pack(push, 4)
struct MmapBuf {
    volatile uint8_t status;
    uint8_t bit;
    int16_t length;
    uint32_t reserve;
    uint64_t kernelNext;
    uint64_t userNext;
    uint8_t data[kBufData];
};
#pragma pack(pop)
static_assert(sizeof(MmapBuf) == 1024);

constexpr int kRate = 24000;
constexpr char kDev[] = "/dev/si_haptic";
constexpr char kSysfs[] = "/sys/bus/i2c/devices/5-006b/";

int64_t nowNs() {
    timespec ts;
    clock_gettime(CLOCK_BOOTTIME, &ts);
    return ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

std::string readSysfs(const char* node) {
    std::string path = std::string(kSysfs) + node;
    FILE* f = fopen(path.c_str(), "r");
    if (!f) return "";
    char buf[512] = {};
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    std::string s(buf, n);
    while (!s.empty() && (s.back() == '\n' || s.back() == ' ')) s.pop_back();
    return s;
}

bool writeSysfs(const char* node, const std::string& value) {
    std::string path = std::string(kSysfs) + node;
    FILE* f = fopen(path.c_str(), "w");
    if (!f) return false;
    bool ok = fputs(value.c_str(), f) >= 0;
    return fclose(f) == 0 && ok;
}

// Value of `key` in a "k=v k=v" or "k = v" sysfs line.
long field(const std::string& line, const char* key) {
    size_t p = line.find(key);
    if (p == std::string::npos) return -1;
    p = line.find('=', p);
    return p == std::string::npos ? -1 : strtol(line.c_str() + p + 1, nullptr, 0);
}

struct Options {
    std::string wave = "kick";
    double freq = 0;  // 0 = tracked f0
    double ms = 40;
    double level = 1.0;
    int kickCycles = 2;
    int brakeCycles = 1;
    double tauMs = 15;
    int gain = 0x80;
    int vboost = -1;   // 1/10 V, -1 = leave
    int brake = -1;    // RTP auto-brake, -1 = leave
    int repeat = 1;
    double gapMs = 400;
    std::string raw;
    std::string file;  // raw s8 at 24 kHz instead of a synthetic wave
    bool header = false;
    std::string label;
    // Stream buffers of `chunk` samples with at most `ahead` queued (0 = as many as fit); the
    // HAL's follow loop uses 120 and 2.
    int chunk = kBufData;
    int ahead = 0;
    // gun
    double rpm = 600;
    // follow: hits every `everyMs`, decaying with `tauMs`, as 5 ms levels
    double everyMs = 300;
    double jitter = 0;       // ±share of each level, as a noisy sound's body wobbles
    double trackGain = 3;    // StreamPlayer kTrackGain
    double knee = 0.28;      // StreamPlayer kKneeNormal: drive at level 1
    double endLevel = 0.03;  // a hit ends below this (tap2 HIT_END)
    double hitMs = 350;      // and after this (tap2 HIT_MAX_MS)
};

// StreamPlayer::runFollow: 5 ms chunks; a rise lands at once, a fall spreads over the chunk; the
// drive is the level plus `gain` × the error against a first-order model of the mass (15 ms).
std::vector<double> renderFollow(const std::vector<double>& levels, double f, double knee, double gain) {
    constexpr int kChunk = 120;
    const double w = 2 * M_PI * f / kRate;
    const double mech = 1 - std::exp(-1.0 / (0.015 * kRate));
    std::vector<double> x;
    double phase = 0, est = 0, wanted = 0;
    for (double level : levels) {
        const double target = level * knee;
        const double from = target > wanted ? target : wanted;
        for (int i = 0; i < kChunk; i++) {
            const double l = from + (target - from) * (i + 1) / kChunk;
            const double d = std::clamp(l + gain * (l - est), -1.0, 1.0);
            x.push_back(d * std::sin(phase));
            est = std::clamp(est + (d - est) * mech, 0.0, knee);
            phase += w;
            if (phase > 2 * M_PI) phase -= 2 * M_PI;
        }
        wanted = target;
    }
    return x;
}

// Signed 8-bit at 24 kHz, the RTP FIFO format.
std::vector<int8_t> synth(const Options& o, double f) {
    if (!o.file.empty()) {
        std::vector<int8_t> out;
        if (FILE* in = fopen(o.file.c_str(), "rb")) {
            int c;
            while ((c = fgetc(in)) != EOF) out.push_back(static_cast<int8_t>(c));
            fclose(in);
        }
        return out;
    }
    const double w = 2 * M_PI * f / kRate;
    const int cycle = static_cast<int>(std::lround(kRate / f));
    int n = static_cast<int>(o.ms * kRate / 1000);
    std::vector<double> x;

    if (o.wave == "gun") {
        // Rounds at `rpm`: kick cycles at full scale, then the body at level decaying with tau.
        const int period = static_cast<int>(std::lround(60.0 / o.rpm * kRate));
        const int kick = o.kickCycles * cycle;
        x.resize(n);
        for (int i = 0; i < n; i++) {
            const int k = i % period;
            const double a = k < kick ? 1.0 : o.level * std::exp(-(k - kick) * 1000.0 / kRate / o.tauMs);
            x[i] = a * std::sin(w * i);
        }
    } else if (o.wave == "follow") {
        // A hit every everyMs at `level`, decaying with tau, until endLevel or hitMs; each 5 ms
        // level wobbles by ±jitter, then the HAL's follow loop renders it.
        uint32_t seed = 12345;
        std::vector<double> levels;
        for (double t = 0; t < o.ms; t += 5) {
            const double since = std::fmod(t, o.everyMs);
            double l = since < o.hitMs ? o.level * std::exp(-since / o.tauMs) : 0;
            if (l < o.endLevel) l = 0;
            seed = seed * 1664525u + 1013904223u;
            const double r = (seed >> 8) / double(1 << 24) * 2 - 1;
            if (l > 0 && since >= 5) l = std::clamp(l * (1 + o.jitter * r), 0.0, 1.0);
            levels.push_back(l);
        }
        levels.insert(levels.end(), 8, 0.0);  // falls to rest, braked
        x = renderFollow(levels, f, o.knee, o.trackGain);
    } else if (o.wave == "sine" || o.wave == "rumble") {
        x.resize(n);
        for (int i = 0; i < n; i++) {
            double fade = std::min({1.0, i / double(cycle), (n - 1 - i) / double(cycle)});
            x[i] = o.level * fade * std::sin(w * i);
        }
    } else if (o.wave == "burst") {
        // Gunshot: instant attack, exponential decay at the carrier.
        x.resize(n);
        for (int i = 0; i < n; i++)
            x[i] = o.level * std::exp(-i * 1000.0 / kRate / o.tauMs) * std::sin(w * i);
    } else {
        // kick: overdrive cycles at full scale, sustain at level, antiphase brake.
        int body = std::max(n, (o.kickCycles + 1) * cycle);
        int brake = o.brakeCycles * cycle;
        x.resize(body + brake);
        for (int i = 0; i < body; i++)
            x[i] = (i < o.kickCycles * cycle ? 1.0 : o.level) * std::sin(w * i);
        for (int i = 0; i < brake; i++)
            x[body + i] = -std::sin(w * (body + i));
    }

    std::vector<int8_t> out(x.size());
    for (size_t i = 0; i < x.size(); i++)
        out[i] = static_cast<int8_t>(std::clamp(std::lround(x[i] * 127), -127L, 127L));
    return out;
}

struct Sample {
    int64_t t;
    float x, y, z;
};

class Accel {
  public:
    bool start() {
        mThread = std::thread([this] { loop(); });
        for (int i = 0; i < 200 && !mReady; i++) usleep(5000);
        return mReady && mOk;
    }
    void stop() {
        mRun = false;
        if (mThread.joinable()) mThread.join();
    }
    std::vector<Sample> take() {
        std::lock_guard<std::mutex> lock(mLock);
        return std::move(mSamples);
    }
    void clear() {
        std::lock_guard<std::mutex> lock(mLock);
        mSamples.clear();
    }
    double rateHz() const { return mRateHz; }

  private:
    void loop() {
        ALooper* looper = ALooper_prepare(0);
        ASensorManager* sm = ASensorManager_getInstanceForPackage("org.yasvara.haptest");
        const ASensor* s = sm ? ASensorManager_getDefaultSensor(sm, ASENSOR_TYPE_ACCELEROMETER) : nullptr;
        ASensorEventQueue* q = s ? ASensorManager_createEventQueue(sm, looper, 1, nullptr, nullptr) : nullptr;
        if (!q || ASensorEventQueue_registerSensor(q, s, ASensor_getMinDelay(s), 0) < 0) {
            mReady = true;
            return;
        }
        mRateHz = 1e6 / std::max(1, ASensor_getMinDelay(s));
        mOk = true;
        mReady = true;
        ASensorEvent ev[64];
        while (mRun) {
            ALooper_pollOnce(20, nullptr, nullptr, nullptr);
            ssize_t n;
            while ((n = ASensorEventQueue_getEvents(q, ev, 64)) > 0) {
                std::lock_guard<std::mutex> lock(mLock);
                for (ssize_t i = 0; i < n; i++)
                    mSamples.push_back({ev[i].timestamp, ev[i].acceleration.x,
                                        ev[i].acceleration.y, ev[i].acceleration.z});
            }
        }
        ASensorEventQueue_disableSensor(q, s);
        ASensorManager_destroyEventQueue(sm, q);
    }

    std::thread mThread;
    std::atomic<bool> mRun{true}, mReady{false}, mOk{false};
    std::mutex mLock;
    std::vector<Sample> mSamples;
    double mRateHz = 0;
};

class Stream {
  public:
    bool open() {
        mFd = ::open(kDev, O_RDWR | O_CLOEXEC);
        if (mFd < 0) return false;
        void* p = mmap(nullptr, sizeof(MmapBuf) * kBufCount, PROT_READ | PROT_WRITE, MAP_SHARED, mFd, 0);
        if (p == MAP_FAILED) return false;
        mBufs = static_cast<MmapBuf*>(p);
        return true;
    }
    double f0Hz() {
        uint32_t f0 = 0;
        return ioctl(mFd, kIoctlGetF0, &f0) == 0 && f0 > 0 ? f0 / 10.0 : 170.0;
    }
    void gain(int g) { ioctl(mFd, kIoctlSetGain, g); }
    void stop() { ioctl(mFd, kIoctlStop, 0); }

    int pending() const {
        int n = 0;
        for (int i = 0; i < kBufCount; i++) n += mBufs[i].status == kBufValid;
        return n;
    }

    // Returns the time the first buffer was handed over.
    int64_t play(const std::vector<int8_t>& pcm, int chunk, int ahead) {
        ioctl(mFd, kIoctlStream, 0);
        int64_t t0 = 0;
        size_t off = 0;
        int idx = 0;
        while (off < pcm.size()) {
            MmapBuf& b = mBufs[idx];
            for (int spin = 0; b.status == kBufValid || (ahead > 0 && pending() >= ahead); spin++) {
                if (spin > 4000) return t0;  // kernel loop gave up
                usleep(ahead > 0 ? 1000 : 500);
            }
            size_t len = std::min<size_t>(std::clamp(chunk, 1, kBufData), pcm.size() - off);
            memcpy(b.data, pcm.data() + off, len);
            b.length = static_cast<int16_t>(len);
            __atomic_thread_fence(__ATOMIC_RELEASE);
            if (!t0) t0 = nowNs();
            b.status = kBufValid;
            off += len;
            idx = (idx + 1) % kBufCount;
        }
        return t0;
    }

  private:
    int mFd = -1;
    MmapBuf* mBufs = nullptr;
};

struct Metrics {
    double peakG = 0, rmsG = 0, noiseG = 0, onsetMs = -1, ringMs = -1;
    double e60 = 0;  // ∫ a² dt over the 60 ms from onset, g²·ms: what a short tap feels like
    int samples = 0;
};

Metrics analyse(const std::vector<Sample>& s, int64_t t0, double driveMs) {
    Metrics m;
    std::vector<const Sample*> pre, post;
    for (const Sample& e : s) (e.t < t0 ? pre : post).push_back(&e);
    if (pre.size() < 10 || post.empty()) return m;

    double bx = 0, by = 0, bz = 0;
    for (auto* e : pre) bx += e->x, by += e->y, bz += e->z;
    bx /= pre.size(), by /= pre.size(), bz /= pre.size();
    auto dev = [&](const Sample* e) {
        return std::sqrt((e->x - bx) * (e->x - bx) + (e->y - by) * (e->y - by) +
                         (e->z - bz) * (e->z - bz)) / 9.80665;
    };
    double noise = 0;
    for (auto* e : pre) noise = std::max(noise, dev(e));
    m.noiseG = noise;

    const double thr = std::max(2 * noise, 0.02);
    int64_t onset = -1;
    for (auto* e : post) {
        double d = dev(e);
        m.peakG = std::max(m.peakG, d);
        if (onset < 0 && d > thr) onset = e->t;
    }
    if (onset < 0) return m;
    m.onsetMs = (onset - t0) / 1e6;

    const int64_t end = onset + static_cast<int64_t>(driveMs * 1e6);
    double sum = 0;
    int64_t lastLoud = end;
    for (auto* e : post) {
        double d = dev(e);
        if (e->t >= onset && e->t <= end) sum += d * d, m.samples++;
        if (e->t > end && d > std::max(0.1 * m.peakG, thr)) lastLoud = e->t;
    }
    m.rmsG = m.samples ? std::sqrt(sum / m.samples) : 0;
    const Sample* prev = nullptr;
    for (auto* e : post) {
        if (e->t >= onset && e->t <= onset + 60'000'000 && prev) {
            const double d = dev(e);
            m.e60 += d * d * (e->t - prev->t) / 1e6;
        }
        prev = e;
    }
    m.ringMs = (lastLoud - end) / 1e6;
    return m;
}

void usage() {
    fprintf(stderr,
            "usage: haptest [--wave kick|burst|sine|rumble] [--freq Hz] [--ms N] [--level 0..1]\n"
            "               [--kick N] [--brake-cycles N] [--tau ms] [--gain 0..255]\n"
            "               [--vboost 60..110] [--brake 0|1] [--repeat N] [--gap ms]\n"
            "               [--raw file.csv] [--file wave.s8] [--header] [--label text]\n"
            "               [--chunk samples] [--ahead buffers] (HAL follow: 120, 2)\n"
            "  gun:    --rpm N (kick, then the body at --level decaying with --tau)\n"
            "  follow: --every ms --tau ms --level --jitter 0..1 --track gain --knee 0..1\n"
            "          --end level --hit-ms ms (the HAL's follow loop on game-like hits)\n");
}

}  // namespace

int main(int argc, char** argv) {
    Options o;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        auto next = [&]() -> const char* {
            if (i + 1 >= argc) { usage(); exit(2); }
            return argv[++i];
        };
        if (a == "--wave") o.wave = next();
        else if (a == "--freq") o.freq = atof(next());
        else if (a == "--ms") o.ms = atof(next());
        else if (a == "--level") o.level = atof(next());
        else if (a == "--kick") o.kickCycles = atoi(next());
        else if (a == "--brake-cycles") o.brakeCycles = atoi(next());
        else if (a == "--tau") o.tauMs = atof(next());
        else if (a == "--gain") o.gain = static_cast<int>(strtol(next(), nullptr, 0));
        else if (a == "--vboost") o.vboost = atoi(next());
        else if (a == "--brake") o.brake = atoi(next());
        else if (a == "--repeat") o.repeat = atoi(next());
        else if (a == "--gap") o.gapMs = atof(next());
        else if (a == "--raw") o.raw = next();
        else if (a == "--file") o.file = next(), o.wave = "file";
        else if (a == "--header") o.header = true;
        else if (a == "--label") o.label = next();
        else if (a == "--chunk") o.chunk = atoi(next());
        else if (a == "--ahead") o.ahead = atoi(next());
        else if (a == "--rpm") o.rpm = atof(next());
        else if (a == "--every") o.everyMs = atof(next());
        else if (a == "--jitter") o.jitter = atof(next());
        else if (a == "--track") o.trackGain = atof(next());
        else if (a == "--knee") o.knee = atof(next());
        else if (a == "--end") o.endLevel = atof(next());
        else if (a == "--hit-ms") o.hitMs = atof(next());
        else { usage(); return 2; }
    }

    if (o.header)
        printf("wave,freq,ms,level,gain,vboost,brake,trial,peak_g,rms_g,noise_g,onset_ms,ring_ms,"
               "samples,accel_hz,ocp,uvp,otp,backoffs,lra_mohm,e60_g2ms,label\n");

    if (o.vboost > 0) writeSysfs("drv_vboost", std::to_string(o.vboost));
    if (o.brake >= 0) writeSysfs("brake_ctrl", "2 " + std::to_string(o.brake));  // SIH_RTP_MODE

    Stream stream;
    if (!stream.open()) {
        perror(kDev);
        return 1;
    }
    Accel accel;
    if (!accel.start()) {
        fprintf(stderr, "accelerometer unavailable\n");
        return 1;
    }

    const double f = o.freq > 0 ? o.freq : stream.f0Hz();
    const std::vector<int8_t> pcm = synth(o, f);
    const double driveMs = pcm.size() * 1000.0 / kRate;
    const long vboost = field(readSysfs("drv_vboost"), "drv_vboost");
    const long brake = field(readSysfs("brake_ctrl"), "brake_state");
    FILE* raw = o.raw.empty() ? nullptr : fopen(o.raw.c_str(), "w");
    if (raw) fprintf(raw, "trial,t_ms,x,y,z\n");

    stream.gain(o.gain);
    for (int trial = 0; trial < o.repeat; trial++) {
        accel.clear();
        usleep(200 * 1000);  // baseline
        int64_t t0 = stream.play(pcm, o.chunk, o.ahead);
        usleep(static_cast<useconds_t>((driveMs + 150) * 1000));  // FIFO tail, then stop
        stream.stop();
        usleep(150 * 1000);
        std::vector<Sample> s = accel.take();
        Metrics m = analyse(s, t0, driveMs);

        std::string fault = readSysfs("fault");
        // Coil resistance tracks coil temperature (Cu +0.39 %/°C).
        long lra = strtol(readSysfs("lra_resistance").c_str(), nullptr, 10);
        printf("%s,%.1f,%.1f,%.2f,%d,%ld,%ld,%d,%.4f,%.4f,%.4f,%.1f,%.1f,%d,%.0f,%ld,%ld,%ld,%ld,%ld,"
               "%.3f,%s\n",
               o.wave.c_str(), f, driveMs, o.level, o.gain, vboost, brake, trial, m.peakG, m.rmsG,
               m.noiseG, m.onsetMs, m.ringMs, m.samples, accel.rateHz(), field(fault, "ocp"),
               field(fault, "uvp"), field(fault, "otp"), field(fault, "backoffs"), lra, m.e60,
               o.label.c_str());
        fflush(stdout);
        if (raw)
            for (const Sample& e : s)
                fprintf(raw, "%d,%.3f,%.4f,%.4f,%.4f\n", trial, (e.t - t0) / 1e6, e.x, e.y, e.z);
        usleep(static_cast<useconds_t>(o.gapMs * 1000));
    }
    if (raw) fclose(raw);
    accel.stop();
    return 0;
}
