use std::collections::HashMap;

/// A decoded image ready for display.
#[derive(Debug, Clone)]
pub struct DecodedImage {
    pub width: u32,
    pub height: u32,
    /// Pixel data in RGBA8888 format (4 bytes per pixel).
    pub pixels: Vec<u8>,
    /// Optional palette (256 entries of [R, G, B]).
    pub palette: Option<Vec<[u8; 3]>>,
    /// Extra metadata (format-specific).
    pub metadata: HashMap<String, String>,
}

/// Trait for custom image format decoders.
pub trait ImageDecoder: Send + Sync {
    /// Human-readable name (e.g., "BMP Image").
    fn name(&self) -> &str;
    /// Return `true` if this decoder can handle the given data.
    /// `context` may be a filename or parent archive format hint.
    fn matches(&self, header: &[u8], context: &str) -> bool;
    /// Decode the image data into RGBA pixels.
    fn decode(&self, data: &[u8]) -> Result<DecodedImage, String>;
}

/// Registry of image format decoders.
#[derive(Default)]
pub struct ImageDecoderRegistry {
    decoders: Vec<Box<dyn ImageDecoder>>,
}

impl ImageDecoderRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, decoder: Box<dyn ImageDecoder>) {
        self.decoders.push(decoder);
    }

    /// Try to decode data using registered decoders.
    pub fn decode(&self, data: &[u8], context: &str) -> Option<DecodedImage> {
        for decoder in &self.decoders {
            if decoder.matches(data, context)
                && let Ok(img) = decoder.decode(data)
            {
                return Some(img);
            }
        }
        None
    }

    pub fn decoder_names(&self) -> Vec<&str> {
        self.decoders.iter().map(|d| d.name()).collect()
    }
}

/// Create default registry with built-in decoders.
pub fn default_image_registry() -> ImageDecoderRegistry {
    let mut reg = ImageDecoderRegistry::new();
    reg.register(Box::new(BmpDecoder));
    reg.register(Box::new(TgaDecoder));
    reg.register(Box::new(PcxDecoder));
    reg
}

// ---------------------------------------------------------------------------
// Built-in: BMP Decoder
// ---------------------------------------------------------------------------

pub struct BmpDecoder;

impl ImageDecoder for BmpDecoder {
    fn name(&self) -> &str {
        "BMP Image"
    }

    fn matches(&self, header: &[u8], _context: &str) -> bool {
        header.len() >= 2 && &header[0..2] == b"BM"
    }

    fn decode(&self, data: &[u8]) -> Result<DecodedImage, String> {
        if data.len() < 54 {
            return Err("BMP too small".to_string());
        }

        let pixel_offset = u32::from_le_bytes(data[10..14].try_into().unwrap()) as usize;
        let width = i32::from_le_bytes(data[18..22].try_into().unwrap());
        let height = i32::from_le_bytes(data[22..26].try_into().unwrap());
        let bits_per_pixel = u16::from_le_bytes(data[28..30].try_into().unwrap());

        if width <= 0 || width > 16384 {
            return Err(format!("Invalid BMP width: {}", width));
        }
        let width = width as u32;
        let (height, bottom_up) = if height < 0 {
            ((-height) as u32, false)
        } else {
            (height as u32, true)
        };
        if height > 16384 {
            return Err(format!("Invalid BMP height: {}", height));
        }

        let mut pixels = vec![0u8; (width * height * 4) as usize];
        let row_size = ((bits_per_pixel as u32 * width).div_ceil(32) * 4) as usize;

        match bits_per_pixel {
            24 | 32 => {
                let bytes_pp = bits_per_pixel as usize / 8;
                for y in 0..height {
                    let src_y = if bottom_up { height - 1 - y } else { y };
                    let row_start = pixel_offset + src_y as usize * row_size;
                    for x in 0..width {
                        let src = row_start + x as usize * bytes_pp;
                        let dst = (y * width + x) as usize * 4;
                        if src + bytes_pp <= data.len() && dst + 4 <= pixels.len() {
                            pixels[dst] = data[src + 2]; // R
                            pixels[dst + 1] = data[src + 1]; // G
                            pixels[dst + 2] = data[src]; // B
                            pixels[dst + 3] = if bytes_pp == 4 { data[src + 3] } else { 255 };
                        }
                    }
                }
            }
            8 => {
                // 8-bit paletted
                let palette_offset = 54usize; // right after BITMAPINFOHEADER
                let mut palette = Vec::new();
                for i in 0..256 {
                    let po = palette_offset + i * 4;
                    if po + 4 <= data.len() {
                        palette.push([data[po + 2], data[po + 1], data[po]]);
                    } else {
                        palette.push([0, 0, 0]);
                    }
                }
                for y in 0..height {
                    let src_y = if bottom_up { height - 1 - y } else { y };
                    let row_start = pixel_offset + src_y as usize * row_size;
                    for x in 0..width {
                        let src = row_start + x as usize;
                        let dst = (y * width + x) as usize * 4;
                        if src < data.len() && dst + 4 <= pixels.len() {
                            let idx = data[src] as usize;
                            let c = palette.get(idx).copied().unwrap_or([0, 0, 0]);
                            pixels[dst] = c[0];
                            pixels[dst + 1] = c[1];
                            pixels[dst + 2] = c[2];
                            pixels[dst + 3] = 255;
                        }
                    }
                }
            }
            _ => return Err(format!("Unsupported BMP bit depth: {}", bits_per_pixel)),
        }

        Ok(DecodedImage {
            width,
            height,
            pixels,
            palette: None,
            metadata: HashMap::new(),
        })
    }
}

// ---------------------------------------------------------------------------
// Built-in: TGA Decoder (uncompressed)
// ---------------------------------------------------------------------------

pub struct TgaDecoder;

impl ImageDecoder for TgaDecoder {
    fn name(&self) -> &str {
        "TGA Image"
    }

    fn matches(&self, header: &[u8], context: &str) -> bool {
        if context.ends_with(".tga") {
            return header.len() >= 18;
        }
        // TGA has no magic; use heuristic: image type 2 (uncompressed true-color) or 10 (RLE)
        if header.len() < 18 {
            return false;
        }
        let image_type = header[2];
        matches!(image_type, 2 | 10) && (header[16] == 24 || header[16] == 32)
    }

    fn decode(&self, data: &[u8]) -> Result<DecodedImage, String> {
        if data.len() < 18 {
            return Err("TGA too small".to_string());
        }
        let id_len = data[0] as usize;
        let image_type = data[2];
        let width = u16::from_le_bytes(data[12..14].try_into().unwrap()) as u32;
        let height = u16::from_le_bytes(data[14..16].try_into().unwrap()) as u32;
        let bpp = data[16];
        let descriptor = data[17];

        if width == 0 || width > 16384 || height == 0 || height > 16384 {
            return Err("Invalid TGA dimensions".to_string());
        }
        if image_type != 2 {
            return Err(format!("Unsupported TGA type: {}", image_type));
        }

        let bytes_pp = match bpp {
            24 => 3usize,
            32 => 4usize,
            _ => return Err(format!("Unsupported TGA bpp: {}", bpp)),
        };
        let pixel_start = 18usize
            .checked_add(id_len)
            .ok_or_else(|| "TGA ID field offset overflow".to_string())?;
        if pixel_start > data.len() {
            return Err("TGA pixel data starts beyond file".to_string());
        }
        let pixel_bytes = (width as usize)
            .checked_mul(height as usize)
            .and_then(|n| n.checked_mul(bytes_pp))
            .ok_or_else(|| "TGA pixel data size overflow".to_string())?;
        let pixel_end = pixel_start
            .checked_add(pixel_bytes)
            .ok_or_else(|| "TGA pixel data offset overflow".to_string())?;
        if pixel_end > data.len() {
            return Err("TGA pixel data truncated".to_string());
        }
        let top_to_bottom = (descriptor & 0x20) != 0;

        let mut pixels = vec![0u8; (width * height * 4) as usize];
        for y in 0..height {
            let dst_y = if top_to_bottom { y } else { height - 1 - y };
            for x in 0..width {
                let src = pixel_start + (y * width + x) as usize * bytes_pp;
                let dst = (dst_y * width + x) as usize * 4;
                if src + bytes_pp <= data.len() && dst + 4 <= pixels.len() {
                    pixels[dst] = data[src + 2]; // R
                    pixels[dst + 1] = data[src + 1]; // G
                    pixels[dst + 2] = data[src]; // B
                    pixels[dst + 3] = if bytes_pp == 4 { data[src + 3] } else { 255 };
                }
            }
        }

        Ok(DecodedImage {
            width,
            height,
            pixels,
            palette: None,
            metadata: HashMap::new(),
        })
    }
}

// ---------------------------------------------------------------------------
// Built-in: PCX Decoder
// ---------------------------------------------------------------------------

pub struct PcxDecoder;

impl ImageDecoder for PcxDecoder {
    fn name(&self) -> &str {
        "PCX Image"
    }

    fn matches(&self, header: &[u8], context: &str) -> bool {
        context.ends_with(".pcx") || (header.len() >= 4 && header[0] == 0x0A && header[3] == 8)
    }

    fn decode(&self, data: &[u8]) -> Result<DecodedImage, String> {
        if data.len() < 128 {
            return Err("PCX too small".to_string());
        }
        if data[0] != 0x0A {
            return Err("Invalid PCX signature".to_string());
        }

        let _version = data[1];
        let encoding = data[2]; // 1 = RLE
        let bpp = data[3];
        let xmin = u16::from_le_bytes(data[4..6].try_into().unwrap()) as u32;
        let ymin = u16::from_le_bytes(data[6..8].try_into().unwrap()) as u32;
        let xmax = u16::from_le_bytes(data[8..10].try_into().unwrap()) as u32;
        let ymax = u16::from_le_bytes(data[10..12].try_into().unwrap()) as u32;
        let bytes_per_line = u16::from_le_bytes(data[68..70].try_into().unwrap()) as usize;

        let width = xmax - xmin + 1;
        let height = ymax - ymin + 1;

        if width == 0 || width > 16384 || height == 0 || height > 16384 {
            return Err("Invalid PCX dimensions".to_string());
        }

        if bpp != 8 {
            return Err(format!("Unsupported PCX bpp: {}", bpp));
        }

        // Decode RLE pixel data
        let mut indices = vec![0u8; (height as usize) * bytes_per_line];
        let mut src = 128usize;
        let mut dst = 0usize;

        if encoding == 1 {
            while dst < indices.len() && src < data.len() {
                let byte = data[src];
                src += 1;
                if byte >= 0xC0 {
                    let count = (byte & 0x3F) as usize;
                    let value = if src < data.len() {
                        let v = data[src];
                        src += 1;
                        v
                    } else {
                        0
                    };
                    for _ in 0..count {
                        if dst < indices.len() {
                            indices[dst] = value;
                            dst += 1;
                        }
                    }
                } else {
                    indices[dst] = byte;
                    dst += 1;
                }
            }
        }

        // Read 256-color palette from end of file
        let mut palette = vec![[0u8; 3]; 256];
        if data.len() >= 769 && data[data.len() - 769] == 0x0C {
            let pal_start = data.len() - 768;
            for i in 0..256 {
                palette[i] = [
                    data[pal_start + i * 3],
                    data[pal_start + i * 3 + 1],
                    data[pal_start + i * 3 + 2],
                ];
            }
        }

        let mut pixels = vec![0u8; (width * height * 4) as usize];
        for y in 0..height {
            for x in 0..width {
                let idx = indices[y as usize * bytes_per_line + x as usize] as usize;
                let pdst = (y * width + x) as usize * 4;
                if pdst + 4 <= pixels.len() {
                    let c = palette.get(idx).copied().unwrap_or([0, 0, 0]);
                    pixels[pdst] = c[0];
                    pixels[pdst + 1] = c[1];
                    pixels[pdst + 2] = c[2];
                    pixels[pdst + 3] = 255;
                }
            }
        }

        Ok(DecodedImage {
            width,
            height,
            pixels,
            palette: Some(palette),
            metadata: HashMap::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bmp_matches() {
        let d = BmpDecoder;
        assert!(d.matches(b"BM\x00\x00", "test.bmp"));
        assert!(!d.matches(b"PNG", "test.png"));
    }

    #[test]
    fn pcx_matches() {
        let d = PcxDecoder;
        assert!(d.matches(&[0x0A, 5, 1, 8], "image.pcx"));
        assert!(!d.matches(&[0x00, 5, 1, 8], "image.dat"));
    }

    #[test]
    fn tga_rejects_unsupported_bpp_without_panicking() {
        let d = TgaDecoder;
        let mut data = vec![0u8; 18];
        data[2] = 2; // uncompressed true-color
        data[12] = 1; // width = 1
        data[14] = 1; // height = 1
        data[16] = 8; // unsupported for this decoder

        let err = d.decode(&data).unwrap_err();
        assert!(err.contains("Unsupported TGA bpp"));
    }

    #[test]
    fn tga_rejects_truncated_pixel_data() {
        let d = TgaDecoder;
        let mut data = vec![0u8; 18];
        data[2] = 2; // uncompressed true-color
        data[12] = 1; // width = 1
        data[14] = 1; // height = 1
        data[16] = 24;

        let err = d.decode(&data).unwrap_err();
        assert!(err.contains("truncated"));
    }

    #[test]
    fn default_registry_has_decoders() {
        let reg = default_image_registry();
        assert_eq!(reg.decoder_names().len(), 3);
    }
}
