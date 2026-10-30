// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The native end of the Yasvara Xposed seam. libandroid_runtime dlopens this library from
// Zygote's SpecializeCommon, in the child, after the process has been specialized and ART's
// post-fork hooks have run but before any application code does, and only when system_server
// marked the process as scoped. Nothing here replaces Vector's Zygisk module: it is the same job
// (class loader, ART hooks, JNI bridge, hand-off to the Java framework) without a Zygisk host.
#include <common/config.h>
#include <common/logging.h>
#include <core/config_bridge.h>
#include <core/context.h>
#include <core/native_api.h>
#include <elf/elf_image.h>
#include <elf/symbol_cache.h>
#include <jni.h>
#include <jni/jni_bridge.h>

#include <map>
#include <string>

#undef LOG_TAG
#define LOG_TAG "YasvaraXposed"

namespace {

using vector::native::ConfigBridge;
using vector::native::Context;
using vector::native::ElfSymbolCache;
using vector::native::HookInline;
using vector::native::UnhookInline;

// Where the Java half of the framework lives. It is a normal system_ext jar, so it is also
// dexopted at build time and verified like any other platform code.
constexpr const char *kFrameworkJar = "/system_ext/framework/yasvara-xposed.jar";
constexpr const char *kEntryClass = "org.matrix.vector.core.Main";

// This build is not obfuscated, so every name maps to itself. The native bridge only needs the
// XResources prefix to exist; everything else falls back to the unobfuscated default.
class ConfigImpl : public ConfigBridge {
public:
    static void Init() {
        auto impl = std::make_unique<ConfigImpl>();
        impl->map_["android.content.res.XRes"] = "android.content.res.XRes";
        instance_ = std::move(impl);
    }
    std::map<std::string, std::string> &obfuscation_map() override { return map_; }
    void obfuscation_map(std::map<std::string, std::string> m) override { map_ = std::move(m); }

private:
    friend std::unique_ptr<ConfigImpl> std::make_unique<ConfigImpl>();
    ConfigImpl() = default;
    std::map<std::string, std::string> map_;
};

class SeamContext : public Context {
public:
    static SeamContext *Create() {
        auto *self = new SeamContext();
        instance_.reset(self);
        ConfigImpl::Init();
        return self;
    }

    bool Attach(JNIEnv *env, jstring nice_name, jstring app_data_dir, bool is_system) {
        if (!LoadFrameworkLoader(env)) return false;
        InitArtHooker(env, init_info_);
        InitHooks(env);
        SetupEntryClass(env);
        return FindAndCall(env, "forkCommon", "(ZLjava/lang/String;Ljava/lang/String;)V",
                           static_cast<jboolean>(is_system), nice_name, app_data_dir);
    }

protected:
    void LoadDex(JNIEnv *, PreloadedDex &&) override {}

    void SetupEntryClass(JNIEnv *env) override {
        auto entry = FindClassFromLoader(env, inject_class_loader_, kEntryClass);
        if (!entry) {
            LOGE("entry class {} not found in {}", kEntryClass, kFrameworkJar);
            return;
        }
        entry_class_ = lsplant::JNI_NewGlobalRef(env, entry);
    }

private:
    bool LoadFrameworkLoader(JNIEnv *env) {
        auto cl_class = lsplant::JNI_FindClass(env, "java/lang/ClassLoader");
        auto get_system = lsplant::JNI_GetStaticMethodID(env, cl_class.get(), "getSystemClassLoader",
                                                         "()Ljava/lang/ClassLoader;");
        auto parent = lsplant::JNI_CallStaticObjectMethod(env, cl_class.get(), get_system);
        auto dcl_class = lsplant::JNI_FindClass(env, "dalvik/system/DexClassLoader");
        if (!parent || !dcl_class) {
            LOGE("cannot resolve the parent class loader");
            return false;
        }
        auto ctor = lsplant::JNI_GetMethodID(
            env, dcl_class.get(), "<init>",
            "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V");
        auto path = lsplant::ScopedLocalRef(env, env->NewStringUTF(kFrameworkJar));
        auto loader = lsplant::ScopedLocalRef(
            env, env->NewObject(dcl_class.get(), ctor, path.get(), nullptr, nullptr, parent.get()));
        if (env->ExceptionCheck() || !loader) {
            env->ExceptionClear();
            LOGE("cannot open {}", kFrameworkJar);
            return false;
        }
        inject_class_loader_ = env->NewGlobalRef(loader.get());
        return true;
    }

    const lsplant::InitInfo init_info_{
        .inline_hooker =
            [](auto target, auto replace) {
                void *backup = nullptr;
                return HookInline(target, replace, &backup) == 0 ? backup : nullptr;
            },
        .inline_unhooker = [](auto target) { return UnhookInline(target) == 0; },
        .art_symbol_resolver =
            [](auto symbol) { return ElfSymbolCache::GetArt()->getSymbAddress(symbol); },
        .art_symbol_prefix_resolver =
            [](auto symbol) { return ElfSymbolCache::GetArt()->getSymbPrefixFirstAddress(symbol); },
        .generated_class_name = "Vector_",
        .generated_source_name = "Dobby",
    };
};

}  // namespace

// Called once per scoped process by Zygote's SpecializeCommon. Never unloaded: the ART hooks it
// installs jump back into this image.
extern "C" [[gnu::visibility("default")]] jboolean yasvara_xposed_attach(
    JNIEnv *env, jstring nice_name, jstring app_data_dir, jboolean is_system_server) {
    if (Context::GetInstance() != nullptr) return JNI_FALSE;  // already attached
    bool ok = SeamContext::Create()->Attach(env, nice_name, app_data_dir,
                                            is_system_server == JNI_TRUE);
    return ok ? JNI_TRUE : JNI_FALSE;
}
