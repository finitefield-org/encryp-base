plugins {
    id("com.android.library") version "9.1.0"
}

group = "io.github.kazuyoshitoshiya.encrypbase"
version = "0.1.0"

val buildNativeBridge = providers.gradleProperty("encsqlite.buildNativeBridge")
    .map { it.equals("true", ignoreCase = true) }
    .orElse(false)

android {
    namespace = "io.github.kazuyoshitoshiya.encrypbase.android"
    compileSdk = 36

    defaultConfig {
        minSdk = 23
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        if (buildNativeBridge.get()) {
            externalNativeBuild {
                cmake {
                    arguments("-DENCSQLITE_ANDROID_BUILD_NATIVE_BRIDGE=ON")
                }
            }
        }
    }

    buildFeatures {
        buildConfig = false
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    if (buildNativeBridge.get()) {
        externalNativeBuild {
            cmake {
                path = file("CMakeLists.txt")
            }
        }
    }
}

dependencies {
    api("androidx.room:room-runtime:2.8.4")
    api("androidx.sqlite:sqlite:2.6.2")

    androidTestImplementation("androidx.test:core:1.7.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("androidx.test:runner:1.6.2")
}
