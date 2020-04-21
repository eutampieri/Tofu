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
    func testRoundtrip() {
        let data = "example".data(using: .utf8)!

        let password = "password"
        let encrypted = CryptoHelper.encrypt(password: password, data: data)
        let decrypted = CryptoHelper.decrypt(password: password, data: encrypted)

        XCTAssertEqual(data, decrypted)
    }
}
