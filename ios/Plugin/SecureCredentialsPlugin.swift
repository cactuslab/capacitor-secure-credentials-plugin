import Foundation
import Capacitor
import LocalAuthentication

/**
 * Please read the Capacitor iOS Plugin Development Guide
 * here: https://capacitorjs.com/docs/plugins/ios
 */
@objc(SecureCredentialsPlugin)
public class SecureCredentialsPlugin: CAPPlugin {
    
    @objc func putCredential(_ call: CAPPluginCall) {
        let service = call.getString(.kService) ?? ""
        let username = call.getString(.kUsername) ?? ""
        let password = call.getString(.kPassword) ?? ""
        let options = Options(dictionary: call.getObject(.kOptions) ?? [:])        
        
        let searchQuery: [String: Any] = [kSecClass as String: kSecClassInternetPassword,
                                    kSecAttrServer as String: service,
                                    kSecAttrAccount as String: username,
                                    kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(searchQuery as CFDictionary, &item)
        guard status != errSecItemNotFound else {
            
            do {
                try save(service: service, username: username, password: password, options: options)
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
                try delete(service: service, username: username)
                try save(service: service, username: username, password: password, options: options)
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
            try update(service: service, username: username, password: password, options: options)
        } catch let error {
            call.resolve((error as! SecureCredentialsError).toJS())
        }
        
        call.resolve(SecureCredentialsError.noData.toJS())
    }
    
    
    @objc func getCredential(_ call: CAPPluginCall) {
        let service = call.getString(.kService) ?? ""
        let username = call.getString(.kUsername) ?? ""
        
        let query: [String: Any] = [kSecClass as String: kSecClassInternetPassword,
                                    kSecAttrServer as String: service,
                                    kSecAttrAccount as String: username,
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
        
        call.resolve(Success(result: CredentialResult(username: username, service: service, password: password)).toJS())
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
        
        let usernames: [CredentialResult] = existingItem.compactMap({
            if let username = $0[kSecAttrAccount as String] as? String, let passwordData = $0[kSecValueData as String] as? Data, let password = String(data: passwordData, encoding: String.Encoding.utf8) {
                return CredentialResult(username: username, service: service,password:password)
            }
            return nil
        })
        
        let result = Success(result: usernames)
        call.resolve(result.toJS())
    }
    
    @objc func removeCredential(_ call: CAPPluginCall) {
        let service = call.getString(.kService) ?? ""
        let username = call.getString(.kUsername) ?? ""
        
        // Delete
        do {
            try delete(service: service, username: username)
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
    
    private func save(service: String, username: String, password: String, options: Options) throws {
        let passwordData = password.data(using: String.Encoding.utf8)!
        
        let query: [String: Any] = applyOptionsToQuery([
            kSecClass as String: kSecClassInternetPassword,
            kSecAttrAccount as String: username,
            kSecAttrServer as String: service,
            kSecValueData as String: passwordData
        ], options: options)
        
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw SecureCredentialsError.unknown(status: "OSStatus: \(status)")
        }
    }
    
    private func update(service: String, username: String, password: String, options: Options) throws {
        let passwordData = password.data(using: String.Encoding.utf8)!
        
        let searchQuery: [String: Any] = [kSecClass as String: kSecClassInternetPassword,
                                    kSecAttrServer as String: service,
                                    kSecAttrAccount as String: username
                                    ]
    
        let updateQuery: [String: Any] = applyOptionsToQuery([kSecAttrAccount as String: username,
                                                             kSecValueData as String: passwordData], options: options)
        
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

private struct Credentials {
    let username: String
    let service: String
}

private struct CredentialResult : JsAble {
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
    
    init(dictionary: [String: Any]) {
        if let securityLevelString = dictionary[.kSecurityLevel] as? String, let level = SecurityLevel(rawValue: securityLevelString) {
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
}
