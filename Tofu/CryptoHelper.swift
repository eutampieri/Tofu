//
//  CryptoHelper.swift
//  Tofu
//
//  Created by Eugenio Tampieri on 01/04/2020.
//  Copyright © 2020 Calle Erlandsson. All rights reserved.
//

import Foundation

final class CryptoHelper {
    ///https://stackoverflow.com/questions/26845307/generate-random-alphanumeric-string-in-swift
    internal func randomString(length: Int) -> String {
      let letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
      return String((0..<length).map{ _ in letters.randomElement()! })
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
        // MARK: Preparing the encryption/decryption
        /// We're encrypting using AES256, CBC mode
        /// The block size and IV length are the same for AES128 and AES256.
        
        let blockSize = kCCBlockSizeAES128
        let keySize = kCCKeySizeAES256
        let algorithm = CCAlgorithm(kCCAlgorithmAES)
        let options = CCOptions(kCCOptionECBMode | kCCOptionPKCS7Padding)
        
        // MARK: Preparing data for encryption
        
        
        let key = self.passwordToKey(password: password, size: keySize)
        // The key is the hashed password, trimmed/padded to length
        
        let keyBytes = key.withUnsafeBytes { (bytes: UnsafePointer<UInt8>) -> UnsafePointer<UInt8> in
            return bytes
        }
        let dataLength       = Int(data.count)
        let dataBytes        = data.withUnsafeBytes { (bytes: UnsafePointer<UInt8>) -> UnsafePointer<UInt8> in
            return bytes
        }
        var bufferData       = Data(count: Int(dataLength) + blockSize)
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
            algorithm,                  // Algorithm
            options,                    // Options
            keyBytes,                   // key data
            keySize,                    // key length
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
        let ivSize = kCCBlockSizeAES128
        let iv = self.randomString(length: ivSize).data(using: .utf8)!
        return iv + self.cryptoOp(password: password, data: data, operation: CCOperation(kCCEncrypt), iv: iv)
    }
    public func decrypt(password: String, data: Data) -> Data {
        let ivSize = kCCBlockSizeAES128
        let iv = data.subdata(in: 0 ..< ivSize)
        assert(iv.count == ivSize)
        return self.cryptoOp(password: password, data: data.advanced(by: ivSize), operation: CCOperation(kCCDecrypt), iv: iv)
    }
}
