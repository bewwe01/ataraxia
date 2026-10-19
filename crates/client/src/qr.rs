//! QR codes for invite links, rendered as a module matrix the UI draws as SVG rectangles (no
//! remote encoder, no HTML injection).

use crate::{ClientError, Result};

/// Returns (`size`, `size × size` characters of '1'/'0').
pub fn modules(data: &str) -> Result<(usize, String)> {
    let code = qrcode::QrCode::with_error_correction_level(data.as_bytes(), qrcode::EcLevel::M)
        .map_err(|_| ClientError::BadInput)?;
    let size = code.width();
    let s = code
        .to_colors()
        .iter()
        .map(|c| if *c == qrcode::Color::Dark { '1' } else { '0' })
        .collect();
    Ok((size, s))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    #[test]
    fn square_matrix() {
        let (n, m) = super::modules("veil://invite/test").unwrap();
        assert_eq!(m.len(), n * n);
        assert!(m.chars().all(|c| c == '0' || c == '1'));
    }
}
