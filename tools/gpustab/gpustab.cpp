/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */

// gpustab: is the GPU computing correctly at its current clock and voltage?
//
// It runs four deterministic compute workloads (fp32 FMA, integer, memory, texture) back to back
// and checks every workgroup's checksum against a reference. Correct hardware gives the same
// checksums at any clock, so the reference is made once at a safe clock (--make-ref) and every
// other run compares with it (--ref). Without a reference each round is held to the first.
//
// Exit status: 0 every round matched, 1 wrong results, 2 setup failed, 3 the GPU hung or reset.

#include <vulkan/vulkan.h>

#include <algorithm>
#include <chrono>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include "stress.spv.h"

namespace {

constexpr uint32_t kModes = 4;
constexpr const char* kModeNames[kModes] = {"fp32", "int", "mem", "tex"};
// Work per invocation; fixed, so checksums compare between runs.
constexpr uint32_t kIters[kModes] = {1024, 2048, 512, 512};
constexpr uint32_t kLocal = 256;
constexpr uint32_t kMemWords = 16u << 20;  // 64 MB
constexpr uint32_t kTexSide = 1024;
constexpr uint32_t kTexLevels = 11;
constexpr uint32_t kSeed = 0x59415356;  // "YASV"

struct Options {
    double seconds = 30;
    uint32_t groups = 2048;
    int modes = (1 << kModes) - 1;
    std::string ref;
    std::string makeRef;
    double gapMs = 0;  // idle between rounds: load steps stress the rail as much as load does
};

uint32_t Hash(uint32_t x) {
    x ^= x >> 16;
    x *= 0x7feb352du;
    x ^= x >> 15;
    x *= 0x846ca68bu;
    x ^= x >> 16;
    return x;
}

double NowMs() {
    using namespace std::chrono;
    return duration<double, std::milli>(steady_clock::now().time_since_epoch()).count();
}

#define CHECK(call)                                                       \
    do {                                                                  \
        VkResult r_ = (call);                                             \
        if (r_ != VK_SUCCESS) {                                           \
            fprintf(stderr, "gpustab: %s failed: %d\n", #call, r_);       \
            exit(r_ == VK_ERROR_DEVICE_LOST ? 3 : 2);                     \
        }                                                                 \
    } while (0)

struct Gpu {
    VkInstance instance = VK_NULL_HANDLE;
    VkPhysicalDevice physical = VK_NULL_HANDLE;
    VkDevice device = VK_NULL_HANDLE;
    VkQueue queue = VK_NULL_HANDLE;
    uint32_t family = 0;
    VkPhysicalDeviceMemoryProperties memory = {};
    char name[VK_MAX_PHYSICAL_DEVICE_NAME_SIZE] = {};

    uint32_t memoryType(uint32_t bits, VkMemoryPropertyFlags want) const {
        for (uint32_t i = 0; i < memory.memoryTypeCount; i++) {
            if ((bits & (1u << i)) && (memory.memoryTypes[i].propertyFlags & want) == want) return i;
        }
        fprintf(stderr, "gpustab: no memory type %#x\n", want);
        exit(2);
    }
};

Gpu Open() {
    Gpu g;
    VkApplicationInfo app = {VK_STRUCTURE_TYPE_APPLICATION_INFO};
    app.pApplicationName = "gpustab";
    app.apiVersion = VK_API_VERSION_1_1;
    VkInstanceCreateInfo ii = {VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO};
    ii.pApplicationInfo = &app;
    CHECK(vkCreateInstance(&ii, nullptr, &g.instance));
    uint32_t count = 1;
    VkResult r = vkEnumeratePhysicalDevices(g.instance, &count, &g.physical);
    if ((r != VK_SUCCESS && r != VK_INCOMPLETE) || count == 0) {
        fprintf(stderr, "gpustab: no GPU\n");
        exit(2);
    }
    VkPhysicalDeviceProperties props;
    vkGetPhysicalDeviceProperties(g.physical, &props);
    memcpy(g.name, props.deviceName, sizeof(g.name));
    vkGetPhysicalDeviceMemoryProperties(g.physical, &g.memory);
    uint32_t families = 0;
    vkGetPhysicalDeviceQueueFamilyProperties(g.physical, &families, nullptr);
    std::vector<VkQueueFamilyProperties> fp(families);
    vkGetPhysicalDeviceQueueFamilyProperties(g.physical, &families, fp.data());
    g.family = UINT32_MAX;
    for (uint32_t i = 0; i < families && g.family == UINT32_MAX; i++) {
        if (fp[i].queueFlags & VK_QUEUE_COMPUTE_BIT) g.family = i;
    }
    if (g.family == UINT32_MAX) {
        fprintf(stderr, "gpustab: no compute queue\n");
        exit(2);
    }
    const float priority = 1.0f;
    VkDeviceQueueCreateInfo qi = {VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO};
    qi.queueFamilyIndex = g.family;
    qi.queueCount = 1;
    qi.pQueuePriorities = &priority;
    VkDeviceCreateInfo di = {VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO};
    di.queueCreateInfoCount = 1;
    di.pQueueCreateInfos = &qi;
    CHECK(vkCreateDevice(g.physical, &di, nullptr, &g.device));
    vkGetDeviceQueue(g.device, g.family, 0, &g.queue);
    return g;
}

struct Buffer {
    VkBuffer buffer = VK_NULL_HANDLE;
    VkDeviceMemory memory = VK_NULL_HANDLE;
    void* map = nullptr;
};

Buffer MakeBuffer(const Gpu& g, VkDeviceSize size, VkBufferUsageFlags usage) {
    Buffer b;
    VkBufferCreateInfo bi = {VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO};
    bi.size = size;
    bi.usage = usage;
    CHECK(vkCreateBuffer(g.device, &bi, nullptr, &b.buffer));
    VkMemoryRequirements req;
    vkGetBufferMemoryRequirements(g.device, b.buffer, &req);
    VkMemoryAllocateInfo ai = {VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO};
    ai.allocationSize = req.size;
    ai.memoryTypeIndex = g.memoryType(
            req.memoryTypeBits, VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT);
    CHECK(vkAllocateMemory(g.device, &ai, nullptr, &b.memory));
    CHECK(vkBindBufferMemory(g.device, b.buffer, b.memory, 0));
    CHECK(vkMapMemory(g.device, b.memory, 0, VK_WHOLE_SIZE, 0, &b.map));
    return b;
}

struct Texture {
    VkImage image = VK_NULL_HANDLE;
    VkImageView view = VK_NULL_HANDLE;
    VkSampler sampler = VK_NULL_HANDLE;
};

// A mipmapped RGBA8 texture of hashed texels, every level its own pattern.
Texture MakeTexture(const Gpu& g, VkCommandBuffer cb) {
    Texture t;
    VkImageCreateInfo ii = {VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO};
    ii.imageType = VK_IMAGE_TYPE_2D;
    ii.format = VK_FORMAT_R8G8B8A8_UNORM;
    ii.extent = {kTexSide, kTexSide, 1};
    ii.mipLevels = kTexLevels;
    ii.arrayLayers = 1;
    ii.samples = VK_SAMPLE_COUNT_1_BIT;
    ii.tiling = VK_IMAGE_TILING_OPTIMAL;
    ii.usage = VK_IMAGE_USAGE_SAMPLED_BIT | VK_IMAGE_USAGE_TRANSFER_DST_BIT;
    CHECK(vkCreateImage(g.device, &ii, nullptr, &t.image));
    VkMemoryRequirements req;
    vkGetImageMemoryRequirements(g.device, t.image, &req);
    VkMemoryAllocateInfo ai = {VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO};
    ai.allocationSize = req.size;
    ai.memoryTypeIndex = g.memoryType(req.memoryTypeBits, VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT);
    VkDeviceMemory memory;
    CHECK(vkAllocateMemory(g.device, &ai, nullptr, &memory));
    CHECK(vkBindImageMemory(g.device, t.image, memory, 0));

    VkDeviceSize total = 0;
    for (uint32_t l = 0; l < kTexLevels; l++) {
        const uint32_t s = std::max(kTexSide >> l, 1u);
        total += VkDeviceSize(s) * s * 4;
    }
    Buffer staging = MakeBuffer(g, total, VK_BUFFER_USAGE_TRANSFER_SRC_BIT);
    std::vector<VkBufferImageCopy> copies;
    auto* texels = static_cast<uint32_t*>(staging.map);
    VkDeviceSize at = 0;
    for (uint32_t l = 0; l < kTexLevels; l++) {
        const uint32_t s = std::max(kTexSide >> l, 1u);
        for (uint32_t i = 0; i < s * s; i++) texels[at / 4 + i] = Hash(i * 31u + l * 0x10001u);
        VkBufferImageCopy c = {};
        c.bufferOffset = at;
        c.imageSubresource = {VK_IMAGE_ASPECT_COLOR_BIT, l, 0, 1};
        c.imageExtent = {s, s, 1};
        copies.push_back(c);
        at += VkDeviceSize(s) * s * 4;
    }
    VkCommandBufferBeginInfo bi = {VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO};
    bi.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    CHECK(vkBeginCommandBuffer(cb, &bi));
    VkImageMemoryBarrier b = {VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER};
    b.srcQueueFamilyIndex = b.dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
    b.image = t.image;
    b.subresourceRange = {VK_IMAGE_ASPECT_COLOR_BIT, 0, kTexLevels, 0, 1};
    b.oldLayout = VK_IMAGE_LAYOUT_UNDEFINED;
    b.newLayout = VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL;
    b.dstAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT;
    vkCmdPipelineBarrier(cb, VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT, VK_PIPELINE_STAGE_TRANSFER_BIT, 0,
                         0, nullptr, 0, nullptr, 1, &b);
    vkCmdCopyBufferToImage(cb, staging.buffer, t.image, VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,
                           static_cast<uint32_t>(copies.size()), copies.data());
    b.oldLayout = VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL;
    b.newLayout = VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL;
    b.srcAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT;
    b.dstAccessMask = VK_ACCESS_SHADER_READ_BIT;
    vkCmdPipelineBarrier(cb, VK_PIPELINE_STAGE_TRANSFER_BIT, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
                         0, 0, nullptr, 0, nullptr, 1, &b);
    CHECK(vkEndCommandBuffer(cb));
    VkSubmitInfo si = {VK_STRUCTURE_TYPE_SUBMIT_INFO};
    si.commandBufferCount = 1;
    si.pCommandBuffers = &cb;
    CHECK(vkQueueSubmit(g.queue, 1, &si, VK_NULL_HANDLE));
    CHECK(vkQueueWaitIdle(g.queue));
    vkDestroyBuffer(g.device, staging.buffer, nullptr);
    vkFreeMemory(g.device, staging.memory, nullptr);

    VkImageViewCreateInfo vi = {VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO};
    vi.image = t.image;
    vi.viewType = VK_IMAGE_VIEW_TYPE_2D;
    vi.format = ii.format;
    vi.subresourceRange = b.subresourceRange;
    CHECK(vkCreateImageView(g.device, &vi, nullptr, &t.view));
    VkSamplerCreateInfo si2 = {VK_STRUCTURE_TYPE_SAMPLER_CREATE_INFO};
    si2.magFilter = si2.minFilter = VK_FILTER_LINEAR;
    si2.mipmapMode = VK_SAMPLER_MIPMAP_MODE_LINEAR;
    si2.addressModeU = si2.addressModeV = si2.addressModeW = VK_SAMPLER_ADDRESS_MODE_REPEAT;
    si2.maxLod = static_cast<float>(kTexLevels);
    CHECK(vkCreateSampler(g.device, &si2, nullptr, &t.sampler));
    return t;
}

void Usage() {
    fprintf(stderr,
            "usage: gpustab [--seconds N] [--groups N] [--modes fp32,int,mem,tex] [--gap-ms N]\n"
            "               [--make-ref FILE | --ref FILE]\n");
    exit(2);
}

Options Parse(int argc, char** argv) {
    Options o;
    for (int i = 1; i < argc; i++) {
        const std::string a = argv[i];
        const auto value = [&]() -> const char* {
            if (i + 1 >= argc) Usage();
            return argv[++i];
        };
        if (a == "--seconds") {
            o.seconds = atof(value());
        } else if (a == "--groups") {
            o.groups = static_cast<uint32_t>(atoi(value()));
        } else if (a == "--gap-ms") {
            o.gapMs = atof(value());
        } else if (a == "--ref") {
            o.ref = value();
        } else if (a == "--make-ref") {
            o.makeRef = value();
        } else if (a == "--modes") {
            o.modes = 0;
            const std::string list = value();
            for (uint32_t m = 0; m < kModes; m++) {
                if (list.find(kModeNames[m]) != std::string::npos) o.modes |= 1 << m;
            }
            if (o.modes == 0) Usage();
        } else {
            Usage();
        }
    }
    if (o.groups == 0 || o.seconds <= 0) Usage();
    return o;
}

}  // namespace

int main(int argc, char** argv) {
    const Options o = Parse(argc, argv);
    Gpu g = Open();

    VkCommandPoolCreateInfo pi = {VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO};
    pi.flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;
    pi.queueFamilyIndex = g.family;
    VkCommandPool pool;
    CHECK(vkCreateCommandPool(g.device, &pi, nullptr, &pool));
    VkCommandBufferAllocateInfo ci = {VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO};
    ci.commandPool = pool;
    ci.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    ci.commandBufferCount = 1;
    VkCommandBuffer cb;
    CHECK(vkAllocateCommandBuffers(g.device, &ci, &cb));

    Buffer mem = MakeBuffer(g, VkDeviceSize(kMemWords) * 4, VK_BUFFER_USAGE_STORAGE_BUFFER_BIT);
    auto* words = static_cast<uint32_t*>(mem.map);
    for (uint32_t i = 0; i < kMemWords; i++) words[i] = Hash(i ^ kSeed);
    const VkDeviceSize sumsSize = VkDeviceSize(o.groups) * 4 * kModes;
    Buffer sums = MakeBuffer(g, sumsSize, VK_BUFFER_USAGE_STORAGE_BUFFER_BIT);
    Texture tex = MakeTexture(g, cb);

    VkDescriptorSetLayoutBinding bindings[3] = {};
    for (uint32_t i = 0; i < 3; i++) {
        bindings[i].binding = i;
        bindings[i].descriptorCount = 1;
        bindings[i].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
        bindings[i].descriptorType = i < 2 ? VK_DESCRIPTOR_TYPE_STORAGE_BUFFER
                                           : VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER;
    }
    VkDescriptorSetLayoutCreateInfo li = {VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO};
    li.bindingCount = 3;
    li.pBindings = bindings;
    VkDescriptorSetLayout layout;
    CHECK(vkCreateDescriptorSetLayout(g.device, &li, nullptr, &layout));
    const VkPushConstantRange push = {VK_SHADER_STAGE_COMPUTE_BIT, 0, 16};
    VkPipelineLayoutCreateInfo pli = {VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO};
    pli.setLayoutCount = 1;
    pli.pSetLayouts = &layout;
    pli.pushConstantRangeCount = 1;
    pli.pPushConstantRanges = &push;
    VkPipelineLayout pipeLayout;
    CHECK(vkCreatePipelineLayout(g.device, &pli, nullptr, &pipeLayout));
    VkShaderModuleCreateInfo mi = {VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO};
    mi.codeSize = sizeof(kStress);
    mi.pCode = kStress;
    VkShaderModule module;
    CHECK(vkCreateShaderModule(g.device, &mi, nullptr, &module));
    VkComputePipelineCreateInfo cpi = {VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO};
    cpi.stage.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    cpi.stage.stage = VK_SHADER_STAGE_COMPUTE_BIT;
    cpi.stage.module = module;
    cpi.stage.pName = "main";
    cpi.layout = pipeLayout;
    VkPipeline pipeline;
    CHECK(vkCreateComputePipelines(g.device, VK_NULL_HANDLE, 1, &cpi, nullptr, &pipeline));

    const VkDescriptorPoolSize sizes[] = {{VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, 2 * kModes},
                                          {VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER, kModes}};
    VkDescriptorPoolCreateInfo dpi = {VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO};
    dpi.maxSets = kModes;
    dpi.poolSizeCount = 2;
    dpi.pPoolSizes = sizes;
    VkDescriptorPool dpool;
    CHECK(vkCreateDescriptorPool(g.device, &dpi, nullptr, &dpool));
    // One set per mode, each writing its own slice of `sums`.
    VkDescriptorSet sets[kModes];
    for (uint32_t m = 0; m < kModes; m++) {
        VkDescriptorSetAllocateInfo ai = {VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO};
        ai.descriptorPool = dpool;
        ai.descriptorSetCount = 1;
        ai.pSetLayouts = &layout;
        CHECK(vkAllocateDescriptorSets(g.device, &ai, &sets[m]));
        const VkDescriptorBufferInfo memInfo = {mem.buffer, 0, VK_WHOLE_SIZE};
        const VkDescriptorBufferInfo sumInfo = {sums.buffer, VkDeviceSize(m) * o.groups * 4,
                                                VkDeviceSize(o.groups) * 4};
        const VkDescriptorImageInfo texInfo = {tex.sampler, tex.view,
                                               VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL};
        VkWriteDescriptorSet w[3] = {};
        for (uint32_t i = 0; i < 3; i++) {
            w[i].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
            w[i].dstSet = sets[m];
            w[i].dstBinding = i;
            w[i].descriptorCount = 1;
            w[i].descriptorType = bindings[i].descriptorType;
        }
        w[0].pBufferInfo = &memInfo;
        w[1].pBufferInfo = &sumInfo;
        w[2].pImageInfo = &texInfo;
        vkUpdateDescriptorSets(g.device, 3, w, 0, nullptr);
    }

    // The checksums every round must give: from the reference file, or the first round's.
    std::vector<uint32_t> expected;
    const size_t count = size_t(o.groups) * kModes;
    if (!o.ref.empty()) {
        FILE* f = fopen(o.ref.c_str(), "rb");
        uint32_t header[3] = {};
        if (f == nullptr || fread(header, 4, 3, f) != 3 || header[0] != o.groups ||
            header[1] != kModes || header[2] != kSeed) {
            fprintf(stderr, "gpustab: %s is not a reference for --groups %u\n", o.ref.c_str(),
                    o.groups);
            return 2;
        }
        expected.resize(count);
        if (fread(expected.data(), 4, count, f) != count) {
            fprintf(stderr, "gpustab: %s is short\n", o.ref.c_str());
            return 2;
        }
        fclose(f);
    }

    VkFenceCreateInfo fi = {VK_STRUCTURE_TYPE_FENCE_CREATE_INFO};
    VkFence fence;
    CHECK(vkCreateFence(g.device, &fi, nullptr, &fence));
    printf("gpustab: %s, %u groups x %u, modes", g.name, o.groups, kLocal);
    for (uint32_t m = 0; m < kModes; m++) {
        if (o.modes & (1 << m)) printf(" %s", kModeNames[m]);
    }
    printf(", %s\n", o.ref.empty() ? (o.makeRef.empty() ? "self-check" : "making reference")
                                   : "against reference");
    fflush(stdout);

    const double start = NowMs();
    double lastReport = start;
    uint64_t rounds = 0;
    uint64_t wrongWords = 0;
    uint64_t wrongRounds = 0;
    uint64_t wrongByMode[kModes] = {};
    double roundMs = 0;
    auto* got = static_cast<uint32_t*>(sums.map);
    while (NowMs() - start < o.seconds * 1000.0) {
        const double t0 = NowMs();
        // A submit per workload keeps each one short of the driver's long-job watchdog.
        for (uint32_t m = 0; m < kModes; m++) {
            if (!(o.modes & (1 << m))) continue;
            CHECK(vkResetCommandBuffer(cb, 0));
            VkCommandBufferBeginInfo bi = {VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO};
            bi.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
            CHECK(vkBeginCommandBuffer(cb, &bi));
            vkCmdBindPipeline(cb, VK_PIPELINE_BIND_POINT_COMPUTE, pipeline);
            const uint32_t params[4] = {m, kIters[m], kSeed + m, kMemWords};
            vkCmdBindDescriptorSets(cb, VK_PIPELINE_BIND_POINT_COMPUTE, pipeLayout, 0, 1, &sets[m],
                                    0, nullptr);
            vkCmdPushConstants(cb, pipeLayout, VK_SHADER_STAGE_COMPUTE_BIT, 0, sizeof(params),
                               params);
            vkCmdDispatch(cb, o.groups, 1, 1);
            VkMemoryBarrier mb = {VK_STRUCTURE_TYPE_MEMORY_BARRIER};
            mb.srcAccessMask = VK_ACCESS_SHADER_WRITE_BIT;
            mb.dstAccessMask = VK_ACCESS_HOST_READ_BIT;
            vkCmdPipelineBarrier(cb, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
                                 VK_PIPELINE_STAGE_HOST_BIT, 0, 1, &mb, 0, nullptr, 0, nullptr);
            CHECK(vkEndCommandBuffer(cb));
            VkSubmitInfo si = {VK_STRUCTURE_TYPE_SUBMIT_INFO};
            si.commandBufferCount = 1;
            si.pCommandBuffers = &cb;
            CHECK(vkQueueSubmit(g.queue, 1, &si, fence));
            const VkResult waited =
                    vkWaitForFences(g.device, 1, &fence, VK_TRUE, 10'000'000'000ull);
            if (waited != VK_SUCCESS) {
                printf("RESULT HANG in %s after %" PRIu64 " rounds (%s)\n", kModeNames[m], rounds,
                       waited == VK_ERROR_DEVICE_LOST ? "device lost" : "timeout");
                return 3;
            }
            CHECK(vkResetFences(g.device, 1, &fence));
        }
        roundMs = NowMs() - t0;
        rounds++;

        if (expected.empty()) {
            expected.assign(got, got + count);
        } else {
            uint64_t wrong = 0;
            for (uint32_t m = 0; m < kModes; m++) {
                if (!(o.modes & (1 << m))) continue;
                for (uint32_t i = 0; i < o.groups; i++) {
                    const size_t at = size_t(m) * o.groups + i;
                    if (got[at] != expected[at]) {
                        wrong++;
                        wrongByMode[m]++;
                    }
                }
            }
            wrongWords += wrong;
            wrongRounds += wrong != 0;
        }
        if (!o.makeRef.empty()) break;

        const double now = NowMs();
        if (now - lastReport >= 1000.0) {
            printf("t=%.0fs rounds=%" PRIu64 " round_ms=%.1f wrong_rounds=%" PRIu64
                   " wrong_groups=%" PRIu64 "\n",
                   (now - start) / 1000.0, rounds, roundMs, wrongRounds, wrongWords);
            fflush(stdout);
            lastReport = now;
        }
        if (o.gapMs > 0) {
            std::this_thread::sleep_for(std::chrono::microseconds(int64_t(o.gapMs * 1000)));
        }
    }

    if (!o.makeRef.empty()) {
        FILE* f = fopen(o.makeRef.c_str(), "wb");
        const uint32_t header[3] = {o.groups, kModes, kSeed};
        if (f == nullptr || fwrite(header, 4, 3, f) != 3 ||
            fwrite(expected.data(), 4, count, f) != count || fclose(f) != 0) {
            fprintf(stderr, "gpustab: cannot write %s\n", o.makeRef.c_str());
            return 2;
        }
        printf("RESULT REF %s round_ms=%.1f\n", o.makeRef.c_str(), roundMs);
        return 0;
    }
    printf("RESULT %s rounds=%" PRIu64 " round_ms=%.1f wrong_rounds=%" PRIu64 " wrong_groups=%" PRIu64,
           wrongRounds == 0 ? "PASS" : "FAIL", rounds, roundMs, wrongRounds, wrongWords);
    for (uint32_t m = 0; m < kModes; m++) {
        if (wrongByMode[m] != 0) printf(" %s=%" PRIu64, kModeNames[m], wrongByMode[m]);
    }
    printf("\n");
    return wrongRounds == 0 ? 0 : 1;
}
