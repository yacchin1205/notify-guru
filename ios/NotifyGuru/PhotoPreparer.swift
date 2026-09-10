import Foundation
import ImageIO
import UniformTypeIdentifiers

enum PhotoPreparer {
    static func load(_ provider: NSItemProvider) async throws -> PreparedPhoto {
        guard let type = provider.registeredTypeIdentifiers.first(where: { UTType($0)?.conforms(to: .image) == true }) else {
            throw ProtocolError.invalidResponse("This item is not a supported image.")
        }
        let data: Data = try await withCheckedThrowingContinuation { continuation in
            provider.loadDataRepresentation(forTypeIdentifier: type) { data, error in
                if let error { continuation.resume(throwing: error) }
                else if let data { continuation.resume(returning: data) }
                else { continuation.resume(throwing: ProtocolError.invalidResponse("The image could not be loaded.")) }
            }
        }
        guard let photo = prepare(data) else {
            throw ProtocolError.invalidResponse("The image could not be prepared within the attachment limit.")
        }
        return photo
    }

    private static let maximumInputBytes = 64 * 1024 * 1024
    private static let preferredJPEGBytes = 1024 * 1024
    private static let maximumJPEGBytes = 2 * 1024 * 1024 - 16

    static func prepare(_ data: Data) -> PreparedPhoto? {
        guard !data.isEmpty, data.count <= maximumInputBytes,
              let source = CGImageSourceCreateWithData(data as CFData, nil) else { return nil }
        var maximumPixelSize = 2048
        var quality = 0.82
        for attempt in 0..<10 {
            let options: [CFString: Any] = [
                kCGImageSourceCreateThumbnailFromImageAlways: true,
                kCGImageSourceCreateThumbnailWithTransform: true,
                kCGImageSourceThumbnailMaxPixelSize: maximumPixelSize,
                kCGImageSourceShouldCacheImmediately: true,
            ]
            guard let image = CGImageSourceCreateThumbnailAtIndex(source, 0, options as CFDictionary),
                  let jpeg = jpegData(image, quality: quality) else { return nil }
            if jpeg.count <= preferredJPEGBytes || (attempt == 9 && jpeg.count <= maximumJPEGBytes) {
                return PreparedPhoto(jpeg: jpeg, width: image.width, height: image.height)
            }
            if quality > 0.55 {
                quality -= 0.09
            } else {
                maximumPixelSize = max(1, Int((Double(maximumPixelSize) * 0.82).rounded()))
            }
        }
        return nil
    }

    private static func jpegData(_ image: CGImage, quality: Double) -> Data? {
        let data = NSMutableData()
        guard let destination = CGImageDestinationCreateWithData(
            data, UTType.jpeg.identifier as CFString, 1, nil
        ) else { return nil }
        CGImageDestinationAddImage(
            destination,
            image,
            [kCGImageDestinationLossyCompressionQuality: quality] as CFDictionary
        )
        guard CGImageDestinationFinalize(destination) else { return nil }
        return data as Data
    }
}
