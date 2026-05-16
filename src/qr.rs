//! QR-code decoding for TOTP enrollment.
//!
//! 2FA setup pages show a QR that encodes an `otpauth://totp/...` URI.
//! Rather than make the user dig out the "manual entry" Base32 secret, we
//! let them point us at a screenshot / saved image of that QR. Pure-Rust
//! decode (`image` + `rqrr`), no webcam, no native deps.

use std::path::Path;

/// Decode the first QR code found in an image file and return its text
/// payload (for our purposes, the `otpauth://` URI). Returns a
/// human-readable error string on any failure so the GUI can show it.
pub fn decode_file(path: &Path) -> Result<String, String> {
    let img = image::open(path).map_err(|e| format!("can't open image: {}", e))?;
    let luma = img.to_luma8();
    let (w, h) = luma.dimensions();
    // Feed rqrr a raw greyscale buffer via its closure API instead of the
    // `image`-integration path — that integration is pinned to image 0.24
    // while eframe drags in image 0.25, so the trait impl doesn't line up.
    let mut prepared = rqrr::PreparedImage::prepare_from_greyscale(
        w as usize,
        h as usize,
        |x, y| luma.get_pixel(x as u32, y as u32).0[0],
    );
    let grids = prepared.detect_grids();
    if grids.is_empty() {
        return Err("no QR code found in that image".to_string());
    }
    // Take the first decodable grid. Most screenshots have exactly one.
    let mut last_err = String::from("QR code found but could not be decoded");
    for g in grids {
        match g.decode() {
            Ok((_meta, content)) => return Ok(content),
            Err(e) => last_err = format!("QR decode failed: {}", e),
        }
    }
    Err(last_err)
}
