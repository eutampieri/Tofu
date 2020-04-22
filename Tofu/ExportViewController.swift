//
//  ExportViewController.swift
//  Tofu
//
//  Created by Eugenio Tampieri on 21/04/2020.
//  Copyright © 2020 Calle Erlandsson. All rights reserved.
//

private func errorDialog(message: String) -> UIAlertController {
    let alert = UIAlertController(title: "Error", message: message, preferredStyle: UIAlertController.Style.alert)
    let alertAction = UIAlertAction(title: "Ok", style: UIAlertAction.Style.default)
    {
        (UIAlertAction) -> Void in
    }
    alert.addAction(alertAction)
    return alert
}

import Foundation
import UIKit
class ExportViewController: UIViewController {
    @IBOutlet weak var password: UITextField!
    @IBOutlet weak var qrToggle: UISwitch!
    weak var keychain: Keychain! = nil
    
    @IBAction func handleExport(_ sender: UIButton) {
        let password = self.password.text!
        let crypted: Bool = password != ""
        let export: Data
        do {
            if crypted {
                export = try self.keychain.export(password: password)
            } else {
                export = try self.keychain.uncryptedExport()
            }
        } catch {
            present(errorDialog(message: "Could not export the keychain"), animated: true)
            return
        }
        if qrToggle.isOn {
            // Export to QR
        } else {
            // Export to file
            // We want to save the file to a temporary location, so we have an URL to share
            
            let fileManager = FileManager.default
            do {
                let filename = try fileManager.url(for: .documentDirectory, in: .userDomainMask, appropriateFor: nil, create: true).appendingPathComponent("keychain.tofu")
                try export.write(to: filename, options: .atomic)

                let shareVC = UIActivityViewController(activityItems: [filename], applicationActivities: [])
                shareVC.completionWithItemsHandler = {
                    (_, _, _, _) in
                    // print("\((activity, success, items, error))")
                    // Cleanup when we're done
                    do{
                        try fileManager.removeItem(at: filename)
                    } catch {}
                }
                self.present(shareVC, animated: true)
            } catch {
                present(errorDialog(message: "Could not share the keychain"), animated: true)
            }
        }
    }
}
