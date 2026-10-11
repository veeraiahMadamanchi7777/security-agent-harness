plugins {
    java
    application
}

group = "dev.securityharness"
version = "0.2.0"

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
    }
}

dependencies {
    implementation("com.github.javaparser:javaparser-symbol-solver-core:3.27.0")
    implementation("com.google.code.gson:gson:2.12.1")

    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
}

application {
    mainClass.set("dev.securityharness.Main")
}

tasks.test {
    useJUnitPlatform()
}
