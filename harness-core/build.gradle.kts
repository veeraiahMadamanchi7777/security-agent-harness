plugins {
    java
    application
}

group = "dev.securityharness"
version = "0.1.0"

repositories {
    mavenCentral()
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
    }
}

dependencies {
    implementation("com.github.javaparser:javaparser-symbol-solver-core:3.27.0")

    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
}

application {
    mainClass.set("dev.securityharness.Main")
}

tasks.test {
    useJUnitPlatform()
}
