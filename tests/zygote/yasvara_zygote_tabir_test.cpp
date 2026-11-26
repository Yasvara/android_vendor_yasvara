/*
 * Copyright (C) 2026 The Yasvara Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "yasvara_zygote_tabir.h"

#include <gtest/gtest.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <string>

namespace {

using yasvara::tabir::CloseSharedFds;
using yasvara::tabir::CloseSharedTexts;
using yasvara::tabir::IgnoreWithSharedFds;
using yasvara::tabir::ReuseOrShare;
using yasvara::tabir::SharedText;
using yasvara::tabir::ShareModuleText;
using yasvara::tabir::RuntimeActive;
using yasvara::tabir::ShouldUnmount;
using yasvara::tabir::ZygiskModuleView;
using yasvara::tabir::ZygiskShouldLoad;

constexpr uid_t kBank = 10123;
constexpr uid_t kGame = 10400;
constexpr uint32_t kDeny[] = {10123};
constexpr uint32_t kGameOnly[] = {10400};

ZygiskModuleView AllApps() {
    return ZygiskModuleView{true, 0, nullptr, 0};
}

ZygiskModuleView GameOnly() {
    return ZygiskModuleView{true, 1, kGameOnly, 1};
}

TEST(ZygoteTabir, IdleAkarDoesNoZygiskWork) {
    EXPECT_FALSE(RuntimeActive(false, false, false, false, 0));
    bool denied = true;
    EXPECT_FALSE(ZygiskShouldLoad(kGame, false, false, false, false, false, false, nullptr, 0,
                                  nullptr, 0, &denied));
    EXPECT_FALSE(denied);
}

TEST(ZygoteTabir, ProtectedAppNeverLoads) {
    ZygiskModuleView mods[] = {AllApps()};
    bool denied = false;
    EXPECT_FALSE(ZygiskShouldLoad(kBank, false, false, true, false, false, true, kDeny, 1, mods, 1,
                                  &denied));
    EXPECT_TRUE(denied);
}

TEST(ZygoteTabir, InScopeAppLoads) {
    ZygiskModuleView mods[] = {GameOnly()};
    bool denied = true;
    EXPECT_TRUE(ZygiskShouldLoad(kGame, false, false, true, false, false, true, kDeny, 1, mods, 1,
                                 &denied));
    EXPECT_FALSE(denied);
}

TEST(ZygoteTabir, OutOfScopeAppDoesNotLoad) {
    ZygiskModuleView mods[] = {GameOnly()};
    bool denied = true;
    EXPECT_FALSE(ZygiskShouldLoad(10199, false, false, true, false, false, true, nullptr, 0, mods,
                                  1, &denied));
    EXPECT_FALSE(denied);
}

TEST(ZygoteTabir, ChildZygoteAndIsolatedNeverLoad) {
    ZygiskModuleView mods[] = {AllApps()};
    EXPECT_FALSE(ZygiskShouldLoad(kGame, false, true, true, false, false, true, nullptr, 0, mods, 1,
                                  nullptr));
    EXPECT_FALSE(ZygiskShouldLoad(99001, false, false, true, false, false, true, nullptr, 0, mods,
                                  1, nullptr));
}

TEST(ZygoteTabir, SystemServerLoadsOnlyWhenAModuleTargetsIt) {
    ZygiskModuleView mods[] = {AllApps()};
    EXPECT_TRUE(
            ZygiskShouldLoad(1000, true, false, true, false, false, true, nullptr, 0, mods, 1,
                             nullptr));
    EXPECT_FALSE(
            ZygiskShouldLoad(1000, true, false, true, false, true, true, nullptr, 0, mods, 1,
                             nullptr));
    EXPECT_FALSE(
            ZygiskShouldLoad(1000, true, false, true, false, false, false, nullptr, 0, mods, 1,
                             nullptr));
}

TEST(ZygoteTabir, UnmountFollowsDenyListNotEveryApp) {
    const uint32_t force[] = {kBank};
    EXPECT_TRUE(ShouldUnmount(kBank, false, false, false, false, false, force, 1, nullptr, 0,
                              true));
    EXPECT_FALSE(ShouldUnmount(kGame, false, false, false, false, false, force, 1, nullptr, 0,
                               true));
    EXPECT_FALSE(ShouldUnmount(kBank, false, false, false, false, false, force, 1, nullptr, 0,
                               false));
    EXPECT_FALSE(ShouldUnmount(kBank, true, false, true, false, true, nullptr, 0, nullptr, 0,
                               true));
}

TEST(ZygoteTabir, ModulesWithoutZygiskStillUnmountProtectedApps) {
    EXPECT_TRUE(RuntimeActive(false, true, false, false, 0));
    EXPECT_TRUE(ShouldUnmount(kGame, false, false, false, false, true, nullptr, 0, nullptr, 0,
                              true));
    EXPECT_FALSE(ShouldUnmount(kGame, false, false, false, true, true, nullptr, 0, nullptr, 0,
                               true));
}

std::string WriteTemp(const std::string& bytes) {
    char path[] = "/tmp/yasvara_zygisk_XXXXXX";
    const int fd = mkstemp(path);
    EXPECT_GE(fd, 0);
    EXPECT_EQ(static_cast<ssize_t>(bytes.size()), write(fd, bytes.data(), bytes.size()));
    close(fd);
    return path;
}

TEST(ZygoteTabir, SharedTextIsAnExactSealedCopy) {
    std::string elf(200000, '\0');
    for (size_t i = 0; i < elf.size(); ++i) elf[i] = static_cast<char>(i * 31);
    const std::string path = WriteTemp(elf);
    const int fd = ShareModuleText(path.c_str());
    unlink(path.c_str());
    ASSERT_GE(fd, 0);

    struct stat st = {};
    ASSERT_EQ(0, fstat(fd, &st));
    EXPECT_EQ(static_cast<off_t>(elf.size()), st.st_size);
    std::string back(elf.size(), '\0');
    EXPECT_EQ(static_cast<ssize_t>(elf.size()), pread(fd, back.data(), back.size(), 0));
    EXPECT_EQ(elf, back);

    // A child that reaches the fd cannot change what other apps map.
    EXPECT_LT(pwrite(fd, "x", 1, 0), 0);
    EXPECT_LT(ftruncate(fd, 1), 0);
    EXPECT_EQ(MAP_FAILED, mmap(nullptr, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0));
    void* text = mmap(nullptr, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
    EXPECT_NE(MAP_FAILED, text);
    if (text != MAP_FAILED) munmap(text, 4096);
    EXPECT_NE(0, fcntl(fd, F_GETFD) & FD_CLOEXEC);
    close(fd);
}

TEST(ZygoteTabir, SharedTextFailsClosed) {
    EXPECT_EQ(-1, ShareModuleText(nullptr));
    EXPECT_EQ(-1, ShareModuleText(""));
    EXPECT_EQ(-1, ShareModuleText("/nonexistent/zygisk/arm64-v8a.so"));
}

TEST(ZygoteTabir, ParentIgnoresSharedFdsAndChildClosesThem) {
    const std::vector<int> base = {3, 7};
    EXPECT_EQ(base, IgnoreWithSharedFds(base, {}));
    EXPECT_EQ((std::vector<int>{3, 7, 12, 13}), IgnoreWithSharedFds(base, {12, -1, 13}));

    const std::string path = WriteTemp("module");
    std::vector<int> shared = {ShareModuleText(path.c_str()), -1};
    unlink(path.c_str());
    const int fd = shared[0];
    ASSERT_GE(fd, 0);
    CloseSharedFds(shared);
    EXPECT_TRUE(shared.empty());
    EXPECT_EQ(-1, fcntl(fd, F_GETFD));
}

TEST(ZygoteTabir, UnchangedModuleKeepsItsCopyChangedOneIsRecopied) {
    const std::string a = WriteTemp("module-a");
    const std::string b = WriteTemp("module-b");
    std::vector<SharedText> gen1;
    gen1.push_back(ReuseOrShare(a, gen1));
    gen1.push_back(ReuseOrShare(b, gen1));
    ASSERT_GE(gen1[0].fd, 0);
    ASSERT_GE(gen1[1].fd, 0);
    const int fd_a = gen1[0].fd;
    const int fd_b = gen1[1].fd;

    // b is rewritten with a different size: a new copy; a is untouched: same fd, no copy.
    FILE* f = fopen(b.c_str(), "w");
    ASSERT_NE(nullptr, f);
    fputs("module-b-v2", f);
    fclose(f);
    std::vector<SharedText> gen2;
    gen2.push_back(ReuseOrShare(a, gen1));
    gen2.push_back(ReuseOrShare(b, gen1));
    EXPECT_EQ(fd_a, gen2[0].fd);
    EXPECT_NE(-1, gen2[1].fd);
    EXPECT_EQ(-1, gen1[0].fd) << "taken over, so closing gen1 cannot close it";
    EXPECT_EQ(fd_b, gen1[1].fd) << "stale copy stays with gen1 to be closed";
    char buf[32] = {};
    EXPECT_EQ(11, pread(gen2[1].fd, buf, sizeof(buf), 0));
    EXPECT_STREQ("module-b-v2", buf);

    CloseSharedTexts(gen1);
    EXPECT_EQ(-1, fcntl(fd_b, F_GETFD));
    EXPECT_NE(-1, fcntl(fd_a, F_GETFD));
    CloseSharedTexts(gen2);
    unlink(a.c_str());
    unlink(b.c_str());

    std::vector<SharedText> none;
    EXPECT_EQ(-1, ReuseOrShare("", none).fd);
    EXPECT_EQ(-1, ReuseOrShare("/nonexistent/arm64-v8a.so", none).fd);
}

}  // namespace
