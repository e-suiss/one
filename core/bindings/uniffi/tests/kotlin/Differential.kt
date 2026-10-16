/** T-38 (2): every case of the one-core case file through the Kotlin UniFFI binding, byte for byte. */
package app.suiss.one.core.differential

import app.suiss.one.core.invoke
import java.io.File
import java.util.Base64
import kotlin.system.exitProcess

fun main(args: Array<String>) {
    if (args.size != 1) {
        System.err.println("usage: differential <one-core-differential.tsv>")
        exitProcess(1)
    }
    val decoder = Base64.getDecoder()
    var total = 0
    val differing = mutableListOf<String>()
    for (line in File(args[0]).readLines().filter { it.isNotEmpty() }) {
        val fields = line.split('\t')
        if (fields.size != 4) {
            System.err.println("malformed case line ${total + 1}")
            exitProcess(1)
        }
        total += 1
        val output = invoke(fields[1], decoder.decode(fields[2]))
        if (!output.contentEquals(decoder.decode(fields[3]))) {
            differing.add(fields[0])
        }
    }
    if (total == 0) {
        System.err.println("no cases")
        exitProcess(1)
    }
    differing.forEach { System.err.println("differs: $it") }
    println("kotlin: ${total - differing.size}/$total cases byte-equal")
    exitProcess(if (differing.isEmpty()) 0 else 1)
}
