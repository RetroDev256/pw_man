import java.io.File
import java.security.SecureRandom
import java.security.spec.KeySpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

// ---------- Data Model ----------
class PasswordDatabase(
    var entries: MutableMap<String, String>,
) {
    fun add(
        service: String,
        password: String,
    ) {
        entries[service] = password
    }

    fun get(service: String): String? = entries[service]

    fun serialize(): String {
        val builder = StringBuilder()
        for ((k, v) in entries) {
            builder.append("$k:$v\n")
        }
        return builder.toString()
    }

    companion object {
        fun deserialize(data: String): PasswordDatabase {
            val map = mutableMapOf<String, String>()
            val lines = data.split("\n")
            for (line in lines) {
                if (line.contains(":")) {
                    val parts = line.split(":", limit = 2)
                    map[parts[0]] = parts[1]
                }
            }
            return PasswordDatabase(map)
        }
    }
}

// ---------- Crypto Utilities ----------
object Crypto {
    private const val ITERATIONS = 65536
    private const val KEY_LENGTH = 256

    fun deriveKey(
        password: String,
        salt: ByteArray,
    ): SecretKeySpec {
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val spec: KeySpec = PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH)
        val tmp = factory.generateSecret(spec)
        return SecretKeySpec(tmp.encoded, "AES")
    }

    fun encrypt(
        data: ByteArray,
        key: SecretKeySpec,
    ): Pair<ByteArray, ByteArray> {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val iv = ByteArray(12)
        SecureRandom().nextBytes(iv)
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

// ---------- Main Application ----------
fun main(args: Array<String>) {
    val db_file = File(System.getProperty("user.home") + "/.kpassdb")

    if (args.isEmpty()) {
        println("Usage: --init | --add <service> | --get <service>")
        return
    }

    when (args[0]) { // conditional demonstration
        "--init" -> {
            init_db(db_file)
        }

        "--add" -> {
            if (args.size < 2) {
                println("Specify service name.")
                return
            }

            val service = args[1]

            if (!db_file.exists()) {
                println("No database. Run --init first.")
                return
            }

            print("Master password: ")
            val master = readln()

            val lines = db_file.readLines()
            val salt = Base64.getDecoder().decode(lines[0])
            val iv = Base64.getDecoder().decode(lines[1])
            val encrypted = Base64.getDecoder().decode(lines[2])

            val key = Crypto.deriveKey(master, salt)

            val decrypted =
                try {
                    Crypto.decrypt(encrypted, key, iv)
                } catch (e: Exception) {
                    println("Incorrect master password.")
                    return
                }

            val db = PasswordDatabase.deserialize(String(decrypted))

            print("Password for $service: ")
            val password = readln()

            db.add(service, password)

            val (newEncrypted, newIv) = Crypto.encrypt(db.serialize().toByteArray(), key)

            val output =
                Base64.getEncoder().encodeToString(salt) + "\n" +
                    Base64.getEncoder().encodeToString(newIv) + "\n" +
                    Base64.getEncoder().encodeToString(newEncrypted)

            db_file.writeText(output)
            println("Stored.")
        }

        "--get" -> {
            if (args.size < 2) {
                println("Specify service name.")
                return
            }

            val service = args[1]

            if (!db_file.exists()) {
                println("No database.")
                return
            }

            print("Master password: ")
            val master = readln()

            val lines = db_file.readLines()
            val salt = Base64.getDecoder().decode(lines[0])
            val iv = Base64.getDecoder().decode(lines[1])
            val encrypted = Base64.getDecoder().decode(lines[2])

            val key = Crypto.deriveKey(master, salt)

            val decrypted =
                try {
                    Crypto.decrypt(encrypted, key, iv)
                } catch (e: Exception) {
                    println("Incorrect master password.")
                    return
                }

            val db = PasswordDatabase.deserialize(String(decrypted))
            val result = db.get(service)

            if (result == null) {
                println("No entry for $service")
            } else {
                println("Password for $service: $result")
            }
        }

        else -> {
            println("Unknown flag.")
        }
    }
}

fun init_db(db_file: File) {
    assert(!db_file.exists())

    print("Create master password: ")
    val master = readln()

    val salt = ByteArray(16)
    SecureRandom().nextBytes(salt)

    val key = Crypto.deriveKey(master, salt)
    val db = PasswordDatabase(mutableMapOf())

    val (encrypted, iv) = Crypto.encrypt(db.serialize().toByteArray(), key)

    val output =
        Base64.getEncoder().encodeToString(salt) +
            "\n" +
            Base64.getEncoder().encodeToString(iv) +
            "\n" +
            Base64.getEncoder().encodeToString(encrypted)

    db_file.writeText(output)
    println("Database initialized.")
}
