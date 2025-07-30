import XCTest
@testable import SwiftNATDetector

final class SwiftNATTypeDetectorTests: XCTestCase {
    func testExample() throws {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct
        // results.
//        XCTAssertEqual(SwiftNATTypeDetector().text, "Hello, World!")
        var localIp = ""
        for interface in NetworkInterfaces.enumerate() {
            print("\(interface.name):  \(interface.ip)")
            localIp = interface.ip
            break
        }
        
        
        
        
        let result = StunClient.query5780(localIP: localIp,stunHost: "stun.hot-chilli.net")

        print(111,result.natType)
        print(result.ipAddr)
    }
}
