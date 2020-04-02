import Foundation

private func archivedDataWithAccount(_ account: Account) -> Data {
    let data = NSMutableData()
    let coder = NSKeyedArchiver(forWritingWith: data)

    coder.encode(account.password.timeBased, forKey: "timeBased")
    let algorithmIdentifier: Int32
    switch account.password.algorithm {
    case .sha1: algorithmIdentifier = 0
    case .sha256: algorithmIdentifier = 1
    case .sha512: algorithmIdentifier = 2
    }
    coder.encode(algorithmIdentifier, forKey: "algorithm")
    coder.encode(Int32(account.password.digits), forKey: "digits")
    coder.encode(account.password.secret, forKey: "secret")
    coder.encode(Int32(account.password.counter), forKey: "counter")
    coder.encode(Int32(account.password.period), forKey: "period")
    coder.encode(account.name, forKey: "name")
    coder.encode(account.issuer, forKey: "issuer")
    coder.finishEncoding()

    var version: UInt8 = 1
    let size = MemoryLayout.size(ofValue: version)
    let versionedData = NSMutableData(bytes: &version, length: size)
    versionedData.append(data as Data)

    return versionedData as Data
}

private func unarchiveAccountWithData(_ data: Data) -> Account? {
    let version = data.first
    guard version == 1 else { return nil }
    let coder = NSKeyedUnarchiver(forReadingWith: data.subdata(in: 1..<data.count))

    guard let secret = coder.decodeObject(forKey: "secret") as? Data else { return nil }

    let password = Password()

    switch coder.decodeInt32(forKey: "algorithm") {
    case 0: password.algorithm = .sha1
    case 1: password.algorithm = .sha256
    case 2: password.algorithm = .sha512
    default: return nil
    }

    password.secret = secret
    password.digits = Int(coder.decodeInt32(forKey: "digits"))
    password.timeBased = coder.decodeBool(forKey: "timeBased")
    password.counter = Int(coder.decodeInt32(forKey: "counter"))
    password.period = Int(coder.decodeInt32(forKey: "period"))

    let account = Account()
    account.name = coder.decodeObject(forKey: "name") as? String
    account.issuer = coder.decodeObject(forKey: "issuer") as? String
    account.password = password
    return account
}

private func accountWithPersistentRef(_ persistentRef: Data) -> Account? {
    let query: [NSString: AnyObject] = [
        kSecClass: kSecClassGenericPassword,
        kSecValuePersistentRef: persistentRef as AnyObject,
        kSecReturnData: kCFBooleanTrue,
    ]
    var result: AnyObject?
    let code = SecItemCopyMatching(query as CFDictionary, &result)
    guard code == errSecSuccess,
        let data = result as? Data,
        let account = unarchiveAccountWithData(data) else { return nil }
    account.persistentRef = persistentRef
    return account
}

class Keychain {
    var accounts: [Account] {
        let query: [NSString: AnyObject] = [
            kSecClass: kSecClassGenericPassword,
            kSecReturnPersistentRef: kCFBooleanTrue,
            kSecMatchLimit: kSecMatchLimitAll,
        ]
        var result: AnyObject?
        let code = SecItemCopyMatching(query as CFDictionary, &result)
        guard code == errSecSuccess, let persistentRefs = result as? [Data] else { return [] }
        return persistentRefs.compactMap { accountWithPersistentRef($0) }
    }

    func insertAccount(_ account: Account) -> Bool {
        let query: [NSString: AnyObject] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrAccount: ProcessInfo().globallyUniqueString as AnyObject,
            kSecAttrDescription: account.description as AnyObject,
            kSecValueData: archivedDataWithAccount(account) as AnyObject,
            kSecAttrAccessible: kSecAttrAccessibleWhenUnlocked,
            kSecReturnPersistentRef: true as AnyObject,
        ]
        var result: AnyObject?
        guard SecItemAdd(query as CFDictionary, &result) == errSecSuccess else { return false }
        account.persistentRef = (result as! Data)
        return true
    }

    func updateAccount(_ account: Account) -> Bool {
        let query: [NSString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecValuePersistentRef: account.persistentRef!
        ]
        let attributes: [NSString: AnyObject] = [
            kSecAttrDescription: account.description as AnyObject,
            kSecValueData: archivedDataWithAccount(account) as AnyObject,
            kSecAttrAccessible: kSecAttrAccessibleWhenUnlocked,
        ]
        return SecItemUpdate(query as CFDictionary, attributes as CFDictionary) == errSecSuccess
    }

    func deleteAccount(_ account: Account) -> Bool {
        let query: [NSString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecValuePersistentRef: account.persistentRef!
        ]
        return SecItemDelete(query as CFDictionary) == errSecSuccess
    }
    
    /// This function exports all accounts into JSON
    func uncryptedExport() throws -> Data {
        let encoder = JSONEncoder()
        return try encoder.encode(self.accounts)
    }
    
    /// This function encrypts the exported data using the provided password
    func export(password: String) throws -> Data {
        // I was "inspired" by https://github.com/DigitalLeaves/CommonCrypto-in-Swift
        let json = try self.uncryptedExport()
        let helper = CryptoHelper()
        return helper.encrypt(password: password, data: json)
    }
}
