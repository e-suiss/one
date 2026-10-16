/// T-38 (2): every case of the one-core case file through the Swift UniFFI binding, byte for byte.
import Foundation

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(1)
}

guard CommandLine.arguments.count == 2 else { fail("usage: differential <one-core-differential.tsv>") }
guard let text = try? String(contentsOfFile: CommandLine.arguments[1], encoding: .utf8) else {
    fail("cannot read \(CommandLine.arguments[1])")
}

var total = 0
var differing: [String] = []
for line in text.split(separator: "\n", omittingEmptySubsequences: true) {
    let fields = line.split(separator: "\t", omittingEmptySubsequences: false).map(String.init)
    guard fields.count == 4,
        let input = Data(base64Encoded: fields[2]),
        let expected = Data(base64Encoded: fields[3])
    else { fail("malformed case line \(total + 1)") }
    total += 1
    if invoke(operation: fields[1], input: input) != expected {
        differing.append(fields[0])
    }
}

guard total > 0 else { fail("no cases") }
for name in differing {
    FileHandle.standardError.write(Data("differs: \(name)\n".utf8))
}
print("swift: \(total - differing.count)/\(total) cases byte-equal")
exit(differing.isEmpty ? 0 : 1)
