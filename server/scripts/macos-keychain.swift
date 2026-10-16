import Foundation
import Security

func fail(_ message: String) -> Never {
  FileHandle.standardError.write(Data((message + "\n").utf8))
  exit(1)
}

let action = CommandLine.arguments[1]
if action == "list" {
  guard CommandLine.arguments.count == 2 else { fail("usage: zerocreds-keychain list") }
  var output: [[String: String]] = []
  for itemClass in [kSecClassGenericPassword, kSecClassInternetPassword] {
    let query: [String: Any] = [
      kSecClass as String: itemClass,
      kSecReturnAttributes as String: true,
      kSecMatchLimit as String: kSecMatchLimitAll,
    ]
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecItemNotFound { continue }
    guard status == errSecSuccess else { exit(status == errSecInteractionNotAllowed || status == errSecAuthFailed ? 4 : 5) }
    let items = (result as? [[String: Any]]) ?? (result as? [String: Any]).map { [$0] } ?? []
    for item in items {
      var safe: [String: String] = [:]
      for (key, attr) in [("account", kSecAttrAccount), ("service", kSecAttrService),
                          ("label", kSecAttrLabel), ("server", kSecAttrServer),
                          ("path", kSecAttrPath)] {
        if let value = item[attr as String] as? String, !value.isEmpty { safe[key] = value }
      }
      if !safe.isEmpty { output.append(safe) }
      if output.count >= 2000 { break }
    }
  }
  let data = try JSONSerialization.data(withJSONObject: output, options: [.sortedKeys])
  FileHandle.standardOutput.write(data)
  exit(0)
}
guard CommandLine.arguments.count == 4 else { fail("usage: zerocreds-keychain set|exists|get SERVICE ACCOUNT") }
let service = CommandLine.arguments[2]
let account = CommandLine.arguments[3]
guard ["set", "exists", "get"].contains(action), !service.isEmpty, !account.isEmpty else { fail("invalid request") }

let identity: [String: Any] = [
  kSecClass as String: kSecClassGenericPassword,
  kSecAttrService as String: service,
  kSecAttrAccount as String: account,
]
if action == "exists" || action == "get" {
  var query = identity
  if action == "get" {
    query[kSecReturnData as String] = true
  } else {
    query[kSecReturnAttributes as String] = true
  }
  query[kSecMatchLimit as String] = kSecMatchLimitOne
  var result: CFTypeRef?
  let status = SecItemCopyMatching(query as CFDictionary, &result)
  if status == errSecSuccess {
    if action == "get", let data = result as? Data {
      FileHandle.standardOutput.write(data)
    }
    exit(0)
  }
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
