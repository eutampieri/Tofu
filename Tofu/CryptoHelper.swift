//
//  CryptoHelper.swift
//  Tofu
//
//  Created by Eugenio Tampieri on 01/04/2020.
//  Copyright © 2020 Calle Erlandsson. All rights reserved.
//

import Foundation

final class CryptoConstants {
    // Use AES256 in CBC mode
    internal static let Algorithm = CCAlgorithm(kCCAlgorithmAES)
    internal static let KeySize = kCCKeySizeAES256
    internal static let Options = CCOptions(kCCOptionECBMode | kCCOptionPKCS7Padding)
    internal static let IVSize = kCCBlockSizeAES128 // ECB mode -> no IV needed
    internal static let BlockSize = kCCBlockSizeAES128 // AES256 uses the same block size as AES128

    internal static let RandomStringCharSource = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
}

// Based on https://github.com/DigitalLeaves/CommonCrypto-in-Swift
final class CryptoHelper {
    // Based on https://stackoverflow.com/questions/26845307/generate-random-alphanumeric-string-in-swift
    internal static func randomString(length: Int) -> String {
        return String((0..<length).map{ _ in CryptoConstants.RandomStringCharSource.randomElement()! })
    }
    
    // Based on https://stackoverflow.com/questions/25388747/sha256-in-swift
    internal static func sha256(data : Data) -> Data {
        var hash = [UInt8](repeating: 0,  count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash)
        }
        return Data(hash)
    }

    /// Transform a password into a key.
    ///
    /// The key is the hashed password, trimmed/padded to length.
    internal static func passwordToKey(password: String, size: Int) -> Data {
        let pwdData = password.data(using: .utf8, allowLossyConversion: true)!
        let hashed = self.sha256(data: pwdData)
        if hashed.count == size {
            return hashed
        } else {
            #warning("Missing implementation and error handling")
            return Data()
        }
    }

    internal static func cryptoOp(password: String, data input: Data, operation: CCOperation, iv: Data) -> Data {
        let key = self.passwordToKey(password: password, size: CryptoConstants.KeySize)
        
        let keyBuffer = key.withUnsafeBytes { return $0 }
        let ivBuffer = iv.withUnsafeBytes { return $0 }

        let inputBuffer = input.withUnsafeBytes { return $0 }

        var output = Data(count: input.count + CryptoConstants.BlockSize)
        let outputBuffer = output.withUnsafeMutableBytes { return $0 }
        
        var nOutputedBytes = 0
        let cryptStatus = CCCrypt(
            operation,
            CryptoConstants.Algorithm,
            CryptoConstants.Options,
            keyBuffer.baseAddress,    // Key
            keyBuffer.count,
            ivBuffer.baseAddress,     // IV
            inputBuffer.baseAddress,  // Input
            inputBuffer.count,
            outputBuffer.baseAddress, // Output
            outputBuffer.count,
            &nOutputedBytes           // Result
        )
        assert(cryptStatus == kCCSuccess)
        return output
    }

    public static func encrypt(password: String, data: Data) -> Data {
        let iv = self.randomString(length: CryptoConstants.IVSize).data(using: .utf8)!
        return iv + self.cryptoOp(password: password, data: data, operation: CCOperation(kCCEncrypt), iv: iv)
    }

    public static func decrypt(password: String, data: Data) -> Data {
        let iv = data.subdata(in: 0 ..< CryptoConstants.IVSize)
        assert(iv.count == CryptoConstants.IVSize)

        let data = data.advanced(by: iv.count)
        return self.cryptoOp(password: password, data: data, operation: CCOperation(kCCDecrypt), iv: iv)
    }
}
