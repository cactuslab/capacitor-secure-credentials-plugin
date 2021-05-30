import Foundation
import Capacitor

/**
 * Please read the Capacitor iOS Plugin Development Guide
 * here: https://capacitorjs.com/docs/plugins/ios
 */
@objc(SecureCredentialsPlugin)
public class SecureCredentialsPlugin: CAPPlugin {

    @objc func putCredential(_ call: CAPPluginCall) {
        let service = call.getString("service") ?? ""

        print("call: \(call) service: \(service)")
    }
}
