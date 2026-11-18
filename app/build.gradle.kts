import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

android {
    namespace = "sealing.wax"
    compileSdk {
        version = release(37)
    }

    defaultConfig {
        applicationId = "sealing.wax"
        minSdk = 24
        targetSdk = 37
        versionCode = 1
        versionName = "1.0"

        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64", "x86")
        }
    }

    buildTypes {
        release {
            optimization {
                // DO NOT drop packageScope entirely: on AGP 9.5.1 a bare
                // `enable = true` makes R8 lose the app/library rooting and
                // strips everything except explicit -keep classes (verified:
                // 107 app classes + all of Tink/ZXing in usage.txt).
                //
                // DO NOT add "kotlin.**" to the scope either: it lets R8
                // vertically merge the kotlin stdlib's package-private
                // multi-facade classes (CollectionsKt__*) and AGP 9.1's
                // default repackaging then moves the merged subclass to the
                // root package — public class extending a package-private
                // superclass across packages, IllegalAccessError at first
                // load (real-device startup crash, twice).
                enable = true
                packageScope = setOf("androidx.**", "kotlinx.**")
            }
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildFeatures {
        compose = true
    }
    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    // ABI 分包:assemble 各产出独立 APK + universal 通用包(文件名带 ABI 段,
    // CI 与发布页路径随之改变)。侧载分发无需按 ABI 拆 versionCode——那是
    // Play 上架的要求,届时再加。
    splits {
        abi {
            isEnable = true
            reset()
            include("arm64-v8a", "armeabi-v7a", "x86_64", "x86")
            isUniversalApk = true
        }
    }
}

dependencies {
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.material.icons.extended)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.tink.android)
    implementation(libs.zxing.core)
    debugImplementation(libs.androidx.compose.ui.tooling)
}