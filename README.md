# Kotlin Password Manager

Add a description of your project here.

## Instructions for Build and Use

Steps to build and/or run the software:

1. Build the project: `gradle build`
2. Navigate to the .jar directory: `cd app/build/libs/`
3. Run the program: `java -jar app.jar`

Instructions for using the software:

1. Run `java -jar app.jar -- --help` to list the supported commands
2. Example: Run `java -jar app.jar -- --init` to initialize the database
3. Example: Run `java -jar app.jar -- --set` to add a password
4. Example: Run `java -jar app.jar -- --get` to fetch a password

## Development Environment

To recreate the development environment, you need the following software and/or libraries with the specified versions:

* Gradle 9.1.0 must be installed
* Kotlin 2.2.0 must be installed
* openjdk 21.0.10 must be installed

## Useful Websites to Learn More

I found these websites useful in developing this software:

* [Kotlin comparison to Java](https://kotlinlang.org/docs/comparison-to-java.html)
* [Kotlin wikipedia article](https://en.wikipedia.org/wiki/Kotlin)
* [Kotlin website](https://kotlinlang.org/)

## Future Work

The following items I plan to fix, improve, and/or add to this project in the future:

* [ ] Lock memory pages and securely erase passwords after I am done using them
* [ ] Convert to incremental, single-service decryptions for added security
* [ ] Add in key splitting (so you need 2/3 passwords, instead of master password, for example)

