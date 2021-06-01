import Foundation
import Capacitor
import LocalAuthentication

/**
 * Please read the Capacitor iOS Plugin Development Guide
 * here: https://capacitorjs.com/docs/plugins/ios
 */
@objc(SecureCredentialsPlugin)
public class SecureCredentialsPlugin: CAPPlugin {
    
    @objc func addCredential(_ call: CAPPluginCall) {
        guard let credential = Credential(jsObject: call.getObject(.kCredential)) else {
            call.resolve(SecureCredentialsError.unknown(status: "Missing Credential Parameters").toJS())
            return
        }
        
        let options = Options(jsObject: call.getObject(.kOptions))
        
        let searchQuery: [String: Any] = [kSecClass as String: kSecClassInternetPassword,
                                          kSecAttrServer as String: credential.service,
                                          kSecAttrAccount as String: credential.username,
                                    kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(searchQuery as CFDictionary, &item)
        guard status != errSecItemNotFound else {
            
            do {
                try save(credential: credential, options: options)
            } catch let error {
                call.resolve((error as! SecureCredentialsError).toJS())
            }
            // save
            return
        }
        guard status != errSecInteractionNotAllowed else {
            // The credential exists but we can't read it because the user hasn't completed an ID check
            // We can safely remove the credential and overwrite it because this library is designed to
            // assume the simplest case.
            do {
                try delete(service: credential.service, username: credential.username)
                try save(credential: credential, options: options)
            } catch let error {
                call.resolve((error as! SecureCredentialsError).toJS())
            }
            return
        }
        guard status == errSecSuccess else {
            call.resolve(SecureCredentialsError.unknown(status: "OSStatus: \(status)").toJS())
            return
        }
        
        // Update
        do {
            try update(credential: credential, options: options)
        } catch let error {
            call.resolve((error as! SecureCredentialsError).toJS())
        }
        
        call.resolve(SecureCredentialsError.noData.toJS())
    }
    
    @objc func setCredentials(_ call: CAPPluginCall) {
        guard let service = call.getString(.kService) else {
            call.resolve(SecureCredentialsError.unknown(status: "Missing Parameter \(String.kService)").toJS())
            return
        }
        
        guard let credentials: [Credential] = call.getArray(.kCredentials, JSObject.self)?.compactMap({ jsValue in
            guard let username = jsValue[.kUsername] as? String, let password = jsValue[.kPassword] as? String else {
                return nil
            }
            return Credential(service: service, username: username, password: password)
        }) else {
            call.resolve(SecureCredentialsError.unknown(status: "Missing Credentials Array").toJS())
            return
        }
        
        let options = Options(jsObject: call.getObject(.kOptions))
        
        removeCredentials(call)
        
        do {
            try credentials.forEach { credential in
                try save(credential: credential, options: options)
            }
        } catch let error {
            call.resolve((error as! SecureCredentialsError).toJS())
            return
        }
        
        call.resolve(BooleanSuccess.toJS())
    }
    
    @objc func getCredential(_ call: CAPPluginCall) {
        guard let identifier = CredentialIdentifier(fromCall: call) else {
            call.resolve(SecureCredentialsError.unknown(status: "Missing Identifier Parameters in Call").toJS())
            return
        }
        
        let query: [String: Any] = [kSecClass as String: kSecClassInternetPassword,
                                    kSecAttrServer as String: identifier.service,
                                    kSecAttrAccount as String: identifier.username,
                                    kSecMatchLimit as String: kSecMatchLimitOne,
                                    kSecReturnAttributes as String: true,
                                    kSecReturnData as String: true]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status != errSecItemNotFound else {
            call.resolve(SecureCredentialsError.noData.toJS())
            return
        }
        guard status == errSecSuccess else {
            call.resolve(SecureCredentialsError.unknown(status: "OSStatus: \(status)").toJS())
            return
        }
        
        guard let existingItem = item as? [String : Any],
            let passwordData = existingItem[kSecValueData as String] as? Data,
            let password = String(data: passwordData, encoding: String.Encoding.utf8)
        else {
            call.resolve(SecureCredentialsError.unknown(status: "Unexpected Data in the the keychain result").toJS())
            return
        }
        
        call.resolve(Success(result: Credential(service: identifier.service, username: identifier.username, password: password)).toJS())
    }
    
    @objc func getCredentials(_ call: CAPPluginCall) {
        let service = call.getString(.kService) ?? ""
        
        let query: [String: Any] = [kSecClass as String: kSecClassInternetPassword,
                                    kSecAttrServer as String: service,
                                    kSecMatchLimit as String: kSecMatchLimitAll,
                                    kSecReturnAttributes as String: true,
                                    kSecReturnData as String: true]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status != errSecItemNotFound else {
            call.resolve([.kUsernames:[]])
            return
        }
        guard status == errSecSuccess else {
            call.resolve(SecureCredentialsError.unknown(status: "OSStatus: \(status)").toJS())
            return
        }
        
        guard let existingItem = item as? [[String : Any]]
        else {
            call.resolve(SecureCredentialsError.unknown(status: "OSStatus: \(status)").toJS())
            return
        }
        
        let usernames: [Credential] = existingItem.compactMap({
            if let username = $0[kSecAttrAccount as String] as? String, let passwordData = $0[kSecValueData as String] as? Data, let password = String(data: passwordData, encoding: String.Encoding.utf8) {
                return Credential(service: service, username: username, password:password)
            }
            return nil
        })
        
        let result = Success(result: usernames)
        call.resolve(result.toJS())
    }
    
    @objc func removeCredential(_ call: CAPPluginCall) {
        guard let identifier = CredentialIdentifier(fromCall: call) else {
            call.resolve(SecureCredentialsError.unknown(status: "Missing Identifier Parameters in Call").toJS())
            return
        }
        
        // Delete
        do {
            try delete(service: identifier.service, username: identifier.username)
        } catch let error {
            call.resolve((error as! SecureCredentialsError).toJS())
        }
        
        call.resolve(BooleanSuccess.toJS())
    }
    
    @objc func removeCredentials(_ call: CAPPluginCall) {
        let service = call.getString(.kService) ?? ""
        
        // Delete
        do {
            try delete(service: service)
        } catch let error {
            call.resolve((error as! SecureCredentialsError).toJS())
        }
        
        call.resolve(BooleanSuccess.toJS())
    }
    
    @objc func canUseSecurityLevel(_ call: CAPPluginCall) {
        guard let securityLevel = SecurityLevel(rawValue: call.getString(.kSecurityLevel, "")) else {
            call.resolve(SecureCredentialsError.unknown(status: "We didn't understand the security level: \(call.getString(.kSecurityLevel, ""))").toJS())
            return
        }
        
        let context = LAContext()
        
        switch securityLevel {
        
        case .L1_Encrypted:
            call.resolve(BooleanSuccess.toJS())
        case .L2_DeviceUnlocked:
            var error: NSError? = nil
            if context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) {
                call.resolve(BooleanSuccess.toJS())
            } else {
                call.resolve(SecureCredentialsError.unavailable(message: "This type is unavailable: \(error?.localizedDescription ?? "no error")").toJS())
            }
        case .L3_UserPresence, .L4_Biometrics:
            var error: NSError? = nil
            if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
                call.resolve(BooleanSuccess.toJS())
            } else {
                call.resolve(SecureCredentialsError.unavailable(message: "This type is unavailable: \(error?.localizedDescription ?? "no error")").toJS())
            }
            call.resolve(BooleanSuccess.toJS())
        }
    }
    
    @objc func maximumAllowedSecurityLevel(_ call: CAPPluginCall) {
        call.resolve(Success(result: maximumSupportedSecurityLevel().rawValue).toJS())
    }
    
    private func maximumSupportedSecurityLevel() -> SecurityLevel {
        let context = LAContext()
        var error: NSError? = nil
        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            return .L4_Biometrics
        }
        error = nil
        if context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) {
            return .L2_DeviceUnlocked
        }
        return .L1_Encrypted
    }
    
    private func applyOptionsToQuery(_ query: [String: Any], options: Options) -> [String: Any] {
        var query = query
                
        switch options.securityLevel {
        case .L1_Encrypted:
            break
        default:
            let access = SecAccessControlCreateWithFlags(nil, // Use the default allocator.
                                                         kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                                         options.securityLevel.secAccessControlFlags,
                                                         nil) // Ignore any error.
            query[kSecAttrAccessControl as String] = access as Any
        }
        
        return query
    }
    
    private func save(credential: Credential, options: Options) throws {
        
        let query: [String: Any] = applyOptionsToQuery([
            kSecClass as String: kSecClassInternetPassword,
            kSecAttrAccount as String: credential.username,
            kSecAttrServer as String: credential.service,
            kSecValueData as String: credential.passwordData
        ], options: options)
        
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw SecureCredentialsError.unknown(status: "OSStatus: \(status)")
        }
    }
    
    private func update(credential: Credential, options: Options) throws {
        
        let searchQuery: [String: Any] = [kSecClass as String: kSecClassInternetPassword,
                                          kSecAttrServer as String: credential.service,
                                          kSecAttrAccount as String: credential.username
                                    ]
    
        let updateQuery: [String: Any] = applyOptionsToQuery([kSecAttrAccount as String: credential.username,
                                                              kSecValueData as String: credential.passwordData], options: options)
        
        let status = SecItemUpdate(searchQuery as CFDictionary, updateQuery as CFDictionary)
        guard status != errSecItemNotFound else { throw SecureCredentialsError.noData }
        guard status == errSecSuccess else { throw SecureCredentialsError.unknown(status: "OSStatus: \(status)") }
    }
    
    private func delete(service: String, username: String? = nil) throws {
        var query: [String: Any] = [kSecClass as String: kSecClassInternetPassword,
                                    kSecAttrServer as String: service]
        if let username = username {
            query[kSecAttrAccount as String] = username
        }
        
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw SecureCredentialsError.unknown(status: "OSStatus: \(status)") }
    }
}

private protocol JsAble {
    func toJS() -> [String: Any]
}

private let BooleanSuccess = Success<Bool>(result: nil)

private struct Success<T> : JsAble {
    let result: T?
    
    func toJS() -> [String: Any] {
        var js: [String: Any] = ["success": true]
        var res: Any?
        if let result = result as? JsAble {
            res = result.toJS()
        } else if let result = result as? [JsAble] {
            res = result.map({$0.toJS()})
        } else if let result = result {
            res = result
        }
        if let res = res {
            js["result"] = res
        }
        return js
    }
}

private struct Failure<T> : JsAble {
    let error: T
    
    func toJS() -> [String: Any] {
        return [
            "success" : false,
            "error" : error
        ]
    }
}

private struct CredentialIdentifier {
    let username: String
    let service: String
    
    init(service: String, username: String) {
        self.service = service
        self.username = username
    }
    
    init?(jsObject: JSObject?) {
        guard let service = jsObject?[.kService] as? String else { return nil }
        guard let username = jsObject?[.kUsername] as? String else { return nil }
        self.init(service: service, username: username)
    }
    
    init?(fromCall call: CAPPluginCall) {
        guard let service = call.getString(.kService) else { return nil }
        guard let username = call.getString(.kUsername) else { return nil }
        self.init(service: service, username: username)
    }
}

private struct Credential : JsAble {
    let username: String
    let service: String
    let password: String
    
    func toJS() -> [String: Any] {
        return [
            "username" : username,
            "password" : password,
            "service" : service
        ]
    }
    
    init(service: String, username: String, password: String) {
        self.service = service
        self.username = username
        self.password = password
    }
    
    init?(jsObject: JSObject?) {
        guard let service = jsObject?[.kService] as? String else { return nil }
        guard let username = jsObject?[.kUsername] as? String else { return nil }
        guard let password = jsObject?[.kPassword] as? String else { return nil }
        self.init(service: service, username: username, password: password)
    }
    
    var passwordData: Data {
        return password.data(using: String.Encoding.utf8)!
    }
}

private enum SecureCredentialsError: Error, JsAble {
    case failedToAccess
    case noData
    case unavailable(message: String)
    case unknown(status: String)
    
    private var jsCode: String {
        switch self {
        case .failedToAccess: return "failedToAccess"
        case .noData: return "no data"
        case .unknown: return "unknown"
        case .unavailable: return "unavailable"
        }
    }
    
    private var jsMessage: String {
        switch self {
        case .failedToAccess: return "We failed to access the keychain"
        case .noData: return "The credentials don't yet exist"
        case .unavailable(let message): return message
        case .unknown(let status): return "Something went wrong 😱: \(status)"
        }
    }
    
    func toJS() -> [String: Any] {
        return [
            "code" : jsCode,
            "error" : jsMessage
        ]
    }
}


private enum SecurityLevel: String {
    case L1_Encrypted = "L1_Encrypted"
    case L2_DeviceUnlocked = "L2_DeviceUnlocked"
    case L3_UserPresence = "L3_UserPresence"
    case L4_Biometrics = "L4_Biometrics"
    
    var secAccessControlFlags: SecAccessControlCreateFlags {
        switch self {
        case .L1_Encrypted:
            return []
        case .L2_DeviceUnlocked:
            return []
        case .L3_UserPresence:
            return .userPresence
        case .L4_Biometrics:
            return .biometryCurrentSet
        }
    }
}

private struct Options {
    let securityLevel : SecurityLevel
    
    init(jsObject: JSObject?) {
        if let securityLevelString = jsObject?[.kSecurityLevel] as? String, let level = SecurityLevel(rawValue: securityLevelString) {
            securityLevel = level
        } else {
            securityLevel = .L4_Biometrics
        }
    }
}

private extension String {
    static let kService = "service"
    static let kUsername = "username"
    static let kPassword = "password"
    static let kOptions = "options"
    static let kSecurityLevel = "securityLevel"
    static let kMinimumSecurityLevel = "minimumSecurityLevel"
    static let kUsernames = "usernames"
    static let kCredential = "credential"
    static let kCredentials = "credentials"
}
