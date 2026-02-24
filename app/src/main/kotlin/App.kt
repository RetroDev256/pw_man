import java.io.Console
import java.io.File
import java.security.SecureRandom
import java.security.spec.KeySpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

// ----------------------------------------------------------------- Data Model

class PasswordDatabase(
    // Classes in kotlin appear kinda like functions in other languages -
    // this also happens to be the state that the class stores, the "entries"
    // being the mapping between services and their associated passwords.
    var entries: MutableMap<String, String>,
) {
    // Sets or overwrites the password for a service
    fun set(
        service: String,
        password: String,
    ) {
        entries[service] = password
    }

    // Retrieves the password for a service
    fun get(service: String): String? = entries[service]

    // Retrieves a list of the database services
    fun list(): List<String> = entries.keys.toList()

    // Serializes the database as a set of newline separated key-value pairs,
    // where each key-value pair is base-64 encoded key, colon, base-64 value.
    fun serialize(): String {
        val builder = StringBuilder()

        for ((k, v) in entries) {
            // This is necessary because the key and/or password could contain
            // the ':' symbol, and we don't want malicious users to break this.
            val k_b64 = Base64.getEncoder().encodeToString(k.toByteArray())
            val v_v64 = Base64.getEncoder().encodeToString(v.toByteArray())
            builder.append("$k_b64:$v_v64\n")
        }

        return builder.toString()
    }

    // Companion objects are nested "singletones" that allow for static class
    // methods in kotlin - so you don't need a password database to deserialize
    // a string, to *create* a password database.
    companion object {
        fun deserialize(data: String): PasswordDatabase {
            // The mapping of services -> passwords
            val map = mutableMapOf<String, String>()

            // Each service/password pair is per-line
            for (line in data.split("\n")) {
                // Skip the last empty line
                if (line.length == 0) continue

                val parts = line.split(":", limit = 2)

                // Base-64 decode the service and password
                val service_bytes = Base64.getDecoder().decode(parts[0])
                val password_bytes = Base64.getDecoder().decode(parts[1])

                // Decode the bytes to the string type, storing in the map
                val service = service_bytes.decodeToString()
                map[service] = password_bytes.decodeToString()
            }

            // Construct the database from the mapping
            return PasswordDatabase(map)
        }
    }
}

// ----------------------------------------------------------- Crypto Utilities

// Not written by me, this object (singleton) performs PBKDF2 key derivation,
// AES-GCM encryption, and uses random IVs for encrypting the data. It also
// has a function to decrypt data, given a key and initialization vector.

object Crypto {
    private const val ITERATIONS = 65536
    private const val KEY_LENGTH = 256

    fun deriveKey(
        password: CharArray,
        salt: ByteArray,
    ): SecretKeySpec {
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val spec: KeySpec = PBEKeySpec(password, salt, ITERATIONS, KEY_LENGTH)
        val tmp = factory.generateSecret(spec)
        return SecretKeySpec(tmp.encoded, "AES")
    }

    fun encrypt(
        data: ByteArray,
        key: SecretKeySpec,
    ): Pair<ByteArray, ByteArray> {
        val iv = ByteArray(12)
        SecureRandom().nextBytes(iv)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
        return Pair(cipher.doFinal(data), iv)
    }

    fun decrypt(
        data: ByteArray,
        key: SecretKeySpec,
        iv: ByteArray,
    ): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
        return cipher.doFinal(data)
    }
}

// ----------------------------------------------------------- Main Application

fun main(args: Array<String>) {
    // File path used for the password database
    val db_path = System.getProperty("user.home") + "/.pwdb"
    // Console (used for password input prompts)
    val console = System.console() ?: error("No console available")

    if (args.isEmpty()) {
        // Supported operations include:
        // - initializing the database (inc. setting master password)
        // - listing out the services that we have passwords stored for
        // - adding (or updating) a password for a service in the DB
        // - getting a password for a service we have stored in the DB
        println("Usage: --init | --list | --get | --set | --help")
        return
    }

    // The `when` keyword is kotlin syntax for an expression-based switch,
    // which is essentially the same thing as a Zig-style switch, but it also
    // allows for some limited pattern matching capabilities.
    when (args[0]) {
        "--init" -> initialize_db(db_path, console)
        "--list" -> list_services(db_path, console)
        "--set" -> set_password(db_path, console)
        "--get" -> get_password(db_path, console)
        "--help" -> print_usage()
    }
}

fun print_usage() {
    println("Usage:")
    println("  --init - Initializes a new password database")
    println("  --list - Lists services stored in the database")
    println("  --set  - Sets a password for a service")
    println("  --help - Prints this usage menu")
}

// List all services that have passwords stored in the database - we will not
// list out the passwords themselves out of security, but the services can
// certainly be known by the user, especially since they have the password.
fun list_services(
    db_path: String,
    console: Console,
) {
    // The "elvis" operator branches on the monad for if it contains some value
    // or "null" - the LHS is passed on if not null, otherwise the right hand
    // expression is evaluated - here we simply return.
    val (db, _, _) = load_db(db_path, console) ?: return

    println("Passwords are stored for these services:")
    for (service in db.list()) {
        print("\"$service\", ")
    }
    println()
}

// Sets a new password to the password database - db_path is the path to the
// password database file, console is the device to read passwords from.
fun set_password(
    db_path: String,
    console: Console,
) {
    // Load the database, returning if it either does not exist,
    // or if we do not have a correct master password input.
    val (db, salt, key) = load_db(db_path, console) ?: return

    print("Enter service name: ")
    val service = readln()

    // Prompt for the new password that should be added to the database
    val prompt = "Enter password for \"$service\": "
    val service_pw = console.readPassword(prompt)
    db.set(service, String(service_pw))

    save_db(db_path, db, salt, key)
    println("Password for \"$service\" has been stored.")
}

// Get input for what service should be retrieved from the password database,
// then load the file and retrieve and print the password if it exists.
fun get_password(
    db_path: String,
    console: Console,
) {
    // The "elvis" operator branches on the monad for if it contains some value
    // or "null" - the LHS is passed on if not null, otherwise the right hand
    // expression is evaluated - here we simply return.
    val (db, _, _) = load_db(db_path, console) ?: return

    print("Enter service name: ")
    val service = readln()

    // The trickiest part of the password manager is deciding how to do secure
    // *output*, not really secure *input* - Instead of copying the password to
    // the clipboard, I've decided to print it to stdout - I figure that it is
    // easier for an attacker to inspect the clipboard rather than viewing the
    // screen, especially on a sane operating system like linux, where the user
    // understands and controls what programs can currently see their screen.
    val password = db.get(service)

    if (password == null) {
        println("No password for $service exists in the password database.")
    } else {
        println("Password: \"$password\"")
    }
}

// Construct a new password database and save it to the db_file, where the
// master password is read from the "console" - so that it can be hidden.
fun initialize_db(
    db_path: String,
    console: Console,
) {
    // Do not overwrite or corrupt an existing database
    if (File(db_path).exists()) {
        println("The password database file already exists.")
        println("Delete this before database initialization.")
        return
    }

    // Construct and encrypt an empty database
    println("1/4 Constructing new database...")
    val db = PasswordDatabase(mutableMapOf())

    // Prompt for a master password, hide input keystrokes - in this case we do
    // not ask for a "confirmation" of the same password, as it is trivial for
    // the user to recreate the file if they typed in the wrong password - they
    // would not lose data in any case, and the #1 problem with confirming a
    // password - that of "caps lock" - actually goes away if you use it later.
    val master_pw = console.readPassword("Enter master password: ")

    // Create a salt for added security - 256 bits was chosen out of paranoia -
    // it is more likely for the encryption to be reverse engineered than for
    // humans to brute force this in the next several centuries.
    println("2/4 Generating salt...")
    val salt = ByteArray(32)
    SecureRandom().nextBytes(salt)

    // Get the AES key from the salt and password
    println("3/4 Deriving key...")
    val key = Crypto.deriveKey(master_pw, salt)

    // Serialize, encrypt, and save the database
    println("4/4 Saving database...")
    save_db(db_path, db, salt, key)

    println("An empty password database file has been constructed.")
}

// Load the password database from a file; db_path is the path to the password
// database, and console is the device for secure password input - returns null
// if the database does not exist, or if the master password was incorrect.
fun load_db(
    db_path: String,
    console: Console,
): Triple<PasswordDatabase, ByteArray, SecretKeySpec>? {
    // File for the password database
    val db_file = File(db_path)

    if (!db_file.exists()) {
        println("The password database file does not exist.")
        println("Create the database file with --init first.")
        return null
    }

    // Prompt for a master password, hide input keystrokes
    val master_pw = console.readPassword("Enter master password: ")

    // Extract the salt, initialization vector, and encrypted database from the
    // password database file - technically this can be a place where the code
    // crashes, (if the input file does not have 3 valid base64 lines,) however
    // we don't really care if it crashes right here, because that would only
    // admit user fault and it would not leak any information as far as I know.
    val lines = db_file.readLines()
    val encrypted = Base64.getDecoder().decode(lines[0])
    val salt = Base64.getDecoder().decode(lines[1])
    val iv = Base64.getDecoder().decode(lines[2])

    // Get the AES key from the salt and password
    val key = Crypto.deriveKey(master_pw, salt)

    // To store the SERIALIZED database in a byte array
    val decrypted: ByteArray

    try {
        // This decryption will throw an error if the key and initialization
        // vector does not correctly decrypt the database. We can use this to
        // see if we have successfully decrypted the database (within reason).
        decrypted = Crypto.decrypt(encrypted, key, iv)
    } catch (_: Exception) {
        // An improvement that could be made is to allow the user to attempt to
        // enter several more passwords until one is correct (up to some number
        // of attempts, of course) - however this is out of scope for this rn.
        println("Incorrect master password.")
        return null
    }

    val db = PasswordDatabase.deserialize(String(decrypted))
    return Triple(db, salt, key)
}

// Save the password database to a file; db_path is the path to the password
// database, db is the actual database object, salt is the bytes stored with
// the initialization vector for secure password stuff, and key is the AES key.
fun save_db(
    db_path: String,
    db: PasswordDatabase,
    salt: ByteArray,
    key: SecretKeySpec,
) {
    // Serialize and encrypt the database
    val db_bytes = db.serialize().toByteArray()
    val (encrypted, iv) = Crypto.encrypt(db_bytes, key)

    // Write and flush to a file
    val db_file = File(db_path)
    val db_w = db_file.printWriter()
    db_w.println(Base64.getEncoder().encodeToString(encrypted))
    db_w.println(Base64.getEncoder().encodeToString(salt))
    db_w.println(Base64.getEncoder().encodeToString(iv))
    db_w.flush()
}
