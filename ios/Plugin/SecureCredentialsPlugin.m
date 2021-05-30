#import <Foundation/Foundation.h>
#import <Capacitor/Capacitor.h>

// Define the plugin using the CAP_PLUGIN Macro, and
// each method the plugin supports using the CAP_PLUGIN_METHOD macro.
CAP_PLUGIN(SecureCredentialsPlugin, "SecureCredentials",
    CAP_PLUGIN_METHOD(getCredential, CAPPluginReturnPromise);
    CAP_PLUGIN_METHOD(getCredentials, CAPPluginReturnPromise);
    CAP_PLUGIN_METHOD(removeCredential, CAPPluginReturnPromise);
    CAP_PLUGIN_METHOD(removeCredentials, CAPPluginReturnPromise);
    CAP_PLUGIN_METHOD(putCredential, CAPPluginReturnPromise);
    CAP_PLUGIN_METHOD(canUseProtection, CAPPluginReturnPromise);
)
