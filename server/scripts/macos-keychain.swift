import Foundation
import Security

func fail(_ message: String) -> Never {
  FileHandle.standardError.write(Data((message + "\n").utf8))
  exit(1)
}

guard CommandLine.arguments.count == 4 else { fail("usage: zerocreds-keychain set|exists SERVICE ACCOUNT") }
let action = CommandLine.arguments[1]
let service = CommandLine.arguments[2]
let account = CommandLine.arguments[3]
guard ["set", "exists"].contains(action), !service.isEmpty, !account.isEmpty else { fail("invalid request") }

let identity: [String: Any] = [
  kSecClass as String: kSecClassGenericPassword,
  kSecAttrService as String: service,
  kSecAttrAccount as String: account,
]
if action == "exists" {
  var query = identity
  query[kSecReturnAttributes as String] = true
  query[kSecMatchLimit as String] = kSecMatchLimitOne
  let status = SecItemCopyMatching(query as CFDictionary, nil)
  if status == errSecSuccess { exit(0) }
  if status == errSecItemNotFound { exit(3) }
  if status == errSecInteractionNotAllowed || status == errSecAuthFailed { exit(4) }
  exit(5)
}

let input = FileHandle.standardInput.readDataToEndOfFile()
guard !input.isEmpty, input.count <= 65536 else { fail("invalid credential payload") }
guard (try? JSONSerialization.jsonObject(with: input)) is [String: Any] else { fail("credential payload must be a JSON object") }
let update = SecItemUpdate(identity as CFDictionary, [kSecValueData as String: input] as CFDictionary)
if update == errSecItemNotFound {
  var item = identity
  item[kSecValueData as String] = input
  item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
  let add = SecItemAdd(item as CFDictionary, nil)
  guard add == errSecSuccess else { fail("Keychain add failed (\(add))") }
} else {
  guard update == errSecSuccess else { fail("Keychain update failed (\(update))") }
}
