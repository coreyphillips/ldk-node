// Simulator-only entry for the isolated regtest qualification bundle.
// iOS 27 requires scene adoption. This replaces only the test app lifecycle;
// the wallet engine, crypto, TCP, Keychain and SQLCipher adapters are unchanged.
import UIKit
import React
import React_RCTAppDelegate
import ReactAppDependencyProvider

@main
class AppDelegate: UIResponder, UIApplicationDelegate {
  func application(
    _ application: UIApplication,
    configurationForConnecting session: UISceneSession,
    options: UIScene.ConnectionOptions
  ) -> UISceneConfiguration {
    let configuration = UISceneConfiguration(name: "Qualification", sessionRole: session.role)
    configuration.delegateClass = QualificationScene.self
    return configuration
  }
}

class QualificationScene: UIResponder, UIWindowSceneDelegate {
  var window: UIWindow?
  private var delegate: QualificationReactDelegate?
  private var factory: RCTReactNativeFactory?

  func scene(
    _ scene: UIScene,
    willConnectTo session: UISceneSession,
    options: UIScene.ConnectionOptions
  ) {
    guard let scene = scene as? UIWindowScene else { return }
    let delegate = QualificationReactDelegate()
    delegate.dependencyProvider = RCTAppDependencyProvider()
    let factory = RCTReactNativeFactory(delegate: delegate)
    self.delegate = delegate
    self.factory = factory
    let window = UIWindow(windowScene: scene)
    self.window = window
    factory.startReactNative(withModuleName: "chicory", in: window, launchOptions: nil)
  }
}

class QualificationReactDelegate: RCTDefaultReactNativeFactoryDelegate {
  override func sourceURL(for bridge: RCTBridge) -> URL? { self.bundleURL() }
  override func bundleURL() -> URL? {
    Bundle.main.url(forResource: "main", withExtension: "jsbundle")
  }
}
