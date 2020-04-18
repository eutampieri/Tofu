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

final class CryptoHelper {
    ///https://stackoverflow.com/questions/26845307/generate-random-alphanumeric-string-in-swift
    internal func randomString(length: Int) -> String {
        return String((0..<length).map{ _ in CryptoConstants.RandomStringCharSource.randomElement()! })
    }
    
    /// https://stackoverflow.com/questions/25388747/sha256-in-swift
    internal func sha256(data : Data) -> Data {
        var hash = [UInt8](repeating: 0,  count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash)
        }
        return Data(hash)
    }

    // Transform a password into a key
    internal func passwordToKey(password: String, size: Int) -> Data {
        let pwdData = password.data(using: .utf8, allowLossyConversion: true)!
        let hashed = self.sha256(data: pwdData)
        if hashed.count == size {
            return hashed
        } else {
            #warning("Missing implementation and error handling")
            return Data()
        }
    }

    internal func cryptoOp(password: String, data: Data, operation: CCOperation, iv: Data) -> Data {
        // MARK: Preparing data for encryption
        
        let key = self.passwordToKey(password: password, size: CryptoConstants.KeySize)
        // The key is the hashed password, trimmed/padded to length
        
        let keyBytes = key.withUnsafeBytes { (bytes: UnsafePointer<UInt8>) -> UnsafePointer<UInt8> in
            return bytes
        }
        let dataLength       = Int(data.count)
        let dataBytes        = data.withUnsafeBytes { (bytes: UnsafePointer<UInt8>) -> UnsafePointer<UInt8> in
            return bytes
        }
        var bufferData       = Data(count: Int(dataLength) + CryptoConstants.BlockSize)
        let bufferPointer    = bufferData.withUnsafeMutableBytes { (bytes: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8> in
            return bytes
        }
        let bufferLength     = size_t(bufferData.count)
        let ivBuffer: UnsafePointer<UInt8>? = iv.withUnsafeBytes({ (bytes: UnsafePointer<UInt8>) -> UnsafePointer<UInt8> in
            return bytes
        })
        var bytesDecrypted   = Int(0)
        
        // MARK: Encrypt
        let cryptStatus = CCCrypt(
            operation,                  // Operation
            CryptoConstants.Algorithm,  // Algorithm
            CryptoConstants.Options,    // Options
            keyBytes,                   // key data
            CryptoConstants.KeySize,    // key length
            ivBuffer,                   // IV buffer
            dataBytes,                  // input data
            dataLength,                 // input length
            bufferPointer,              // output buffer
            bufferLength,               // output buffer length
            &bytesDecrypted             // output bytes decrypted real
        )
        
        return bufferData as Data
    }

    public func encrypt(password: String, data: Data) -> Data {
        let iv = self.randomString(length: CryptoConstants.IVSize).data(using: .utf8)!
        return iv + self.cryptoOp(password: password, data: data, operation: CCOperation(kCCEncrypt), iv: iv)
    }

    public func decrypt(password: String, data: Data) -> Data {
        let iv = data.subdata(in: 0 ..< CryptoConstants.IVSize)
        assert(iv.count == CryptoConstants.IVSize)

        let data = data.advanced(by: iv.count)
        return self.cryptoOp(password: password, data: data, operation: CCOperation(kCCDecrypt), iv: iv)
    }
}
