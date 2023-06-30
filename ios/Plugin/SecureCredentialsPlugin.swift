import Foundation
import Capacitor
import LocalAuthentication

/**
 * Please read the Capacitor iOS Plugin Development Guide
 * here: https://capacitorjs.com/docs/plugins/ios
 */
@objc(SecureCredentialsPlugin)
public class SecureCredentialsPlugin: CAPPlugin {
    
    @objc func setCredential(_ call: CAPPluginCall) {
        guard let service = call.getString(.kService),
              let credential = Credential(jsObject: call.getObject(.kCredential))
        else {
            call.resolve(Failure(error: SecureCredentialsError.params(message: "service and or credentials missing")).toJS())
            return
        }
        
        let options: Options
        do {
            options = try Options(jsObject: call.getObject(.kOptions))
        } catch {
            call.resolve(Failure(error: error).toJS())
            return
        }
        
        let searchQuery: [String: Any] = [kSecClass as String: kSecClassInternetPassword,
                                          kSecAttrServer as String: service,
                                          kSecAttrAccount as String: credential.username,
                                    kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(searchQuery as CFDictionary, &item)
        guard status != errSecItemNotFound else {
            
            do {
                try save(service: service, credential: credential, options: options)
                try addAccount(service: service, username: credential.username)
                call.resolve(Success(result: true).toJS())
            } catch let error {
                call.resolve(Failure(error: error).toJS())
            }
            // save
            return
        }
        guard status != errSecInteractionNotAllowed else {
            // The credential exists but we can't read it because the user hasn't completed an ID check
            // We can safely remove the credential and overwrite it because this library is designed to
            // assume the simplest case.
            do {
                try delete(service: service, username: credential.username)
                try removeAccount(service: service, username: credential.username)
                try save(service: service, credential: credential, options: options)
                try addAccount(service: service, username: credential.username)
                call.resolve(Success(result: true).toJS())
            } catch let error {
                call.resolve(Failure(error: error).toJS())
            }
            return
        }
        guard status == errSecSuccess else {
            call.resolve(Failure(error: SecureCredentialsError.unknown(status: "OSStatus: \(status)")).toJS())
            return
        }
        
        // Update
        do {
            try update(service: service, credential: credential, options: options)
            call.resolve(Success(result: true).toJS())
            return
        } catch let error {
            call.resolve(Failure(error: error).toJS())
        }
        
        call.resolve(Failure(error: SecureCredentialsError.noData).toJS())
    }
    
    @objc func getCredential(_ call: CAPPluginCall) {
        guard let service = call.getString(.kService),
              let username = call.getString(.kUsername)
        else {
            call.resolve(Failure(error: SecureCredentialsError.params(message: "service and or username missing")).toJS())
            return
        }
        
        let query: [String: Any] = [kSecClass as String: kSecClassInternetPassword,
                                    kSecAttrServer as String: service,
                                    kSecAttrAccount as String: username,
                                    kSecMatchLimit as String: kSecMatchLimitOne,
                                    kSecReturnAttributes as String: true,
                                    kSecReturnData as String: true]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status != errSecItemNotFound else {
            call.resolve(Failure(error: SecureCredentialsError.noData).toJS())
            return
        }
        guard status == errSecSuccess else {
            call.resolve(Failure(error: SecureCredentialsError.unknown(status: "OSStatus: \(status)")).toJS())
            return
        }
        
        guard let existingItem = item as? [String : Any],
            let passwordData = existingItem[kSecValueData as String] as? Data,
            let password = String(data: passwordData, encoding: String.Encoding.utf8)
        else {
            call.resolve(Failure(error: SecureCredentialsError.unknown(status: "Unexpected Data in the the keychain result")).toJS())
            return
        }
        
        call.resolve(Success(result: Credential(username: username, password: password)).toJS())
    }
    
    @objc func getUsernames(_ call: CAPPluginCall) {
        let service = call.getString(.kService) ?? ""
        
        do {
            let accounts = try getAccounts(service: service)
            call.resolve(Success(result: accounts).toJS())
        } catch let error {
            call.resolve(Failure(error: error).toJS())
        }
    }
    
    @objc func removeCredential(_ call: CAPPluginCall) {
        guard let service = call.getString(.kService),
              let username = call.getString(.kUsername)
        else {
            call.resolve(Failure(error: SecureCredentialsError.params(message: "service and or username missing")).toJS())
            return
        }
        
        // Delete
        do {
            try delete(service: service, username: username)
            try removeAccount(service: service, username: username)
        } catch let error {
            call.resolve(Failure(error: error).toJS())
        }
        
        call.resolve(BooleanSuccess.toJS())
    }
    
    @objc func removeCredentials(_ call: CAPPluginCall) {
        let service = call.getString(.kService) ?? ""
        
        // Delete
        do {
            try delete(service: service)
            try removeAllAccounts(service: service)
        } catch let error {
            call.resolve(Failure(error: error).toJS())
        }
        
        call.resolve(BooleanSuccess.toJS())
    }
    
    @objc func availableSecurityStrategies(_ call: CAPPluginCall) {
        call.resolve(Success(result: availableSecurityStrategies()).toJS())
    }
    
    @objc func supportedBiometricSensors(_ call: CAPPluginCall) {
        let context = LAContext()
        /** biometryType is populated with a useful value after we run `canEvaluatePolicy` even if the evaluation fails */
        context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        let biometry = context.biometryType
        
        switch (biometry) {
        case .none:
            call.resolve(Success(result: BiometricSensors()).toJS())
        case .touchID:
            call.resolve(Success(result: BiometricSensors(fingerprint: true)).toJS())
        case .faceID:
            call.resolve(Success(result: BiometricSensors(face: true)).toJS())
        @unknown default:
            call.resolve(Success(result: BiometricSensors()).toJS())
        }
    }
    
    private func availableSecurityStrategies() -> [SecurityStrategy] {
        var result: [SecurityStrategy] = []
        
        let context = LAContext()
        var error: NSError? = nil
        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            result.append(SecurityStrategy(name: .UserPresenceBiometrics, level: .L3_UserPresence, biometrics: true, description: "Biometrics user-presence"))
        }
        error = nil
        if context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) {
            /* We can perform L2 and L3 if we can authenticate the device owner */
            result.append(SecurityStrategy(name: .UserPresence, level: .L3_UserPresence, biometrics: false, description: "Device PIN user-presence"))
            result.append(SecurityStrategy(name: .DeviceUnlocked, level: .L2_DeviceUnlocked, biometrics: false, description: "Device Unlocked"))
        }
        
        /* The keychain is always available */
        result.append(SecurityStrategy(name: .Encrypted, level: .L1_Encrypted, biometrics: false, description: "Encrypted"))
        return result
    }
    
    private func applyOptionsToQuery(_ query: [String: Any], options: Options) -> [String: Any] {
        var query = query
                
        switch options.strategy {
        case .Encrypted:
            break
        case .DeviceUnlocked:
            query[kSecAttrAccessControl as String] = SecAccessControlCreateWithFlags(nil, // Use the default allocator.
                                                                                     kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                                                                     [],
                                                                                     nil) // Ignore any error.
            break
        case .UserPresence:
            query[kSecAttrAccessControl as String] = SecAccessControlCreateWithFlags(nil, // Use the default allocator.
                                                                                     kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                                                                     .userPresence,
                                                                                     nil) // Ignore any error.
            break
        case .UserPresenceBiometrics:
            query[kSecAttrAccessControl as String] = SecAccessControlCreateWithFlags(nil, // Use the default allocator.
                                                                                     kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                                                                     .biometryCurrentSet,
                                                                                     nil) // Ignore any error.
            break
        }
        
        return query
    }
    
    private func save(service: String, credential: Credential, options: Options) throws {
        
        let query: [String: Any] = applyOptionsToQuery([
            kSecClass as String: kSecClassInternetPassword,
            kSecAttrAccount as String: credential.username,
            kSecAttrServer as String: service,
            kSecValueData as String: credential.passwordData
        ], options: options)
        
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw SecureCredentialsError.unknown(status: "OSStatus: \(status)")
        }
    }
    
    private func update(service: String, credential: Credential, options: Options) throws {
        
        let searchQuery: [String: Any] = [kSecClass as String: kSecClassInternetPassword,
                                          kSecAttrServer as String: service,
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
    
    private let accountsService = "CapacitorSecureCredentials.AccountList"
    
    private func addAccount(service: String, username: String) throws {
        let credentialsService = "\(service).\(accountsService)"
        try save(service: credentialsService, credential: Credential(username: username, password: username), options: Options(strategy: .Encrypted))
    }
    
    private func removeAccount(service: String, username: String) throws {
        let credentialsService = "\(service).\(accountsService)"
        try delete(service: credentialsService, username: username)
    }
    
    private func removeAllAccounts(service: String) throws {
        let credentialsService = "\(service).\(accountsService)"
        try delete(service: credentialsService)
    }
    
    private func getAccounts(service: String) throws -> [String] {
        let credentialsService = "\(service).\(accountsService)"
        let query: [String: Any] = [kSecClass as String: kSecClassInternetPassword,
                                    kSecAttrServer as String: credentialsService,
                                    kSecMatchLimit as String: kSecMatchLimitAll,
                                    kSecReturnAttributes as String: true]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status != errSecItemNotFound else {
            return []
        }
        guard status == errSecSuccess else {
            throw SecureCredentialsError.unknown(status: "OSStatus: \(status)")
        }
        
        guard let existingItem = item as? [[String : Any]]
        else {
            throw SecureCredentialsError.unknown(status: "Items stored aren't of the right class: \(item?.description ?? "null")")
        }
        
        let usernames: [String] = existingItem.compactMap({
            if let username = $0[kSecAttrAccount as String] as? String {
                return username
            }
            return nil
        })
        
        return usernames
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
        var js: [String: Any] = ["success": false]
        var res: Any?
        if let error = error as? JsAble {
            res = error.toJS()
        } else if let error = error as? [JsAble] {
            res = error.map({$0.toJS()})
        } else {
            res = error
        }
        if let res = res {
            js["error"] = res
        }
        return js
    }
}

private struct Credential : JsAble {
    let username: String
    let password: String
    
    func toJS() -> [String: Any] {
        return [
            "username" : username,
            "password" : password
        ]
    }
    
    init(username: String, password: String) {
        self.username = username
        self.password = password
    }
    
    init?(jsObject: JSObject?) {
        guard let username = jsObject?[.kUsername] as? String else { return nil }
        guard let password = jsObject?[.kPassword] as? String else { return nil }
        self.init(username: username, password: password)
    }
    
    var passwordData: Data {
        return password.data(using: String.Encoding.utf8)!
    }
}

private struct BiometricSensors : JsAble {
    let face: Bool
    let fingerprint: Bool
    let iris: Bool
    
    func toJS() -> [String : Any] {
        return [
            "face": face,
            "fingerprint": fingerprint,
            "iris": iris
        ]
    }
    
    init(face: Bool = false, fingerprint: Bool = false, iris: Bool = false) {
        self.face = face
        self.fingerprint = fingerprint
        self.iris = iris
    }
}

private enum SecureCredentialsError: Error, JsAble {
    case failedToAccess
    case noData
    case unavailable(message: String)
    case params(message: String)
    case unknown(status: String)
    
    private var jsCode: String {
        switch self {
        case .failedToAccess: return "failed to access"
        case .noData: return "no data"
        case .unavailable: return "unavailable"
        case .params: return "params"
        case .unknown: return "unknown"
        }
    }
    
    private var jsMessage: String {
        switch self {
        case .failedToAccess: return "We failed to access the keychain"
        case .noData: return "The credentials don't yet exist"
        case .unavailable(let message): return message
        case .params(let message): return "Invalid parameters: \(message)"
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


private enum SecurityLevel: Int, Comparable {
    static func < (lhs: SecurityLevel, rhs: SecurityLevel) -> Bool {
        return lhs.rawValue < rhs.rawValue
    }
    
    case L1_Encrypted = 1
    case L2_DeviceUnlocked = 2
    case L3_UserPresence = 3
}

private struct SecurityStrategy {
    var name: SecurityStrategyName
    var level: SecurityLevel
    var biometrics: Bool
    var description: String
}

extension SecurityStrategy: JsAble {
    
    func toJS() -> [String : Any] {
        var result: [String : Any] = [:]
        result["name"] = self.name.rawValue
        result["level"] = self.level.rawValue
        result["biometrics"] = self.biometrics
        result["description"] = self.description
        return result
    }
    
}

private enum SecurityStrategyName: String {
    case Encrypted = "Encrypted"
    case DeviceUnlocked = "DeviceUnlocked"
    case UserPresence = "UserPresence"
    case UserPresenceBiometrics = "UserPresenceBiometrics"
}

private struct Options {
    let strategy: SecurityStrategyName
    
    init(jsObject: JSObject?) throws {
        if let strategyValue = jsObject?[.kStrategy] as? String, let strategy = SecurityStrategyName(rawValue: strategyValue) {
            self.strategy = strategy
        } else {
            throw SecureCredentialsError.params(message: "Missing or invalid strategy")
        }
    }
    
    init(strategy: SecurityStrategyName) {
        self.strategy = strategy
    }
}

private extension String {
    static let kService = "service"
    static let kUsername = "username"
    static let kPassword = "password"
    static let kOptions = "options"
    static let kStrategy = "strategy"
    static let kUsernames = "usernames"
    static let kCredential = "credential"
    static let kCredentials = "credentials"
}
