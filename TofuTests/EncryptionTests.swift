//
//  EncryptionTests.swift
//  TofuTests
//
//  Created by Eugenio Tampieri on 02/04/2020.
//  Copyright © 2020 Calle Erlandsson. All rights reserved.
//

import XCTest
@testable import Tofu

class EncryptionTests: XCTestCase {
    func testEncDec() {
        let data = "example".data(using: .utf8)!
        
        let helper = CryptoHelper()
        let password = "password"
        let encrypted = helper.encrypt(password: password, data: data)
        let decrypted = helper.decrypt(password: password, data: encrypted)
        print("\(decrypted.base64EncodedString())")
        
        XCTAssertEqual(data, decrypted)
    }
}
