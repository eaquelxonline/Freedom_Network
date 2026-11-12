// Freedom Network — Gradle settings. Only official repositories: Google Maven (AGP) and Maven Central (Kotlin).
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "FreedomNetwork"

// `-Pfreedom.windowsOnly=true` builds without the Android module (e.g. on a Windows CI runner).
if (providers.gradleProperty("freedom.windowsOnly").orNull == "true" ||
    providers.gradleProperty("thedpi.windowsOnly").orNull == "true"
) {
    include(":Windows")
} else {
    include(":Android", ":Windows")
}
