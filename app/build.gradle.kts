plugins {
    alias(libs.plugins.kotlin.jvm) // Required for kotlin support
    application // Required to build a CLI
}

repositories {
    mavenCentral()
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

application {
    mainClass = "AppKt"
}

tasks.jar {
    manifest { attributes["Main-Class"] = "AppKt" }
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE

    from({
        configurations.runtimeClasspath.get().map {
            if (it.isDirectory) it else zipTree(it)
        }
    })
}
