mod app;
mod dialogs;
mod layout;
mod theme;
mod views;

use eframe::egui;

use app::SleuthreApp;
use theme::{ThemeMode, apply_theme};

fn main() -> eframe::Result {
    env_logger::init();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1280.0, 800.0])
            .with_icon(app_icon()),
        ..Default::default()
    };
    eframe::run_native(
        "Sleuthre",
        options,
        Box::new(|cc| {
            setup_fonts(&cc.egui_ctx);
            apply_theme(&cc.egui_ctx, ThemeMode::Dark);
            Ok(Box::new(SleuthreApp::default()))
        }),
    )
}

fn setup_fonts(ctx: &egui::Context) {
    use egui::epaint::text::{FontInsert, FontPriority, InsertFontFamily};

    ctx.add_font(FontInsert::new(
        "JetBrainsMono",
        egui::FontData::from_static(include_bytes!("../assets/fonts/JetBrainsMono-Regular.ttf")),
        vec![InsertFontFamily {
            family: egui::FontFamily::Monospace,
            priority: FontPriority::Highest,
        }],
    ));

    ctx.add_font(FontInsert::new(
        "Inter",
        egui::FontData::from_static(include_bytes!("../assets/fonts/Inter-Regular.ttf")),
        vec![InsertFontFamily {
            family: egui::FontFamily::Proportional,
            priority: FontPriority::Highest,
        }],
    ));
}

fn app_icon() -> egui::IconData {
    const SIZE_U32: u32 = 64;
    const SIZE: usize = SIZE_U32 as usize;
    let mut rgba = vec![0_u8; SIZE * SIZE * 4];

    let bg_top = [11_u8, 19_u8, 31_u8, 255_u8];
    let bg_bottom = [24_u8, 53_u8, 82_u8, 255_u8];
    let border = [80_u8, 130_u8, 170_u8, 255_u8];
    let lens = [106_u8, 230_u8, 255_u8, 255_u8];
    let handle = [214_u8, 226_u8, 237_u8, 255_u8];
    let accent = [248_u8, 198_u8, 88_u8, 255_u8];

    for y in 0..SIZE {
        for x in 0..SIZE {
            let t = y as f32 / (SIZE - 1) as f32;
            let shade =
                1.0 - (((x as f32 - 31.5).powi(2) + (y as f32 - 31.5).powi(2)).sqrt() / 65.0);
            let shade = shade.clamp(0.75, 1.0);
            let idx = (y * SIZE + x) * 4;
            rgba[idx] = lerp_channel(bg_top[0], bg_bottom[0], t, shade);
            rgba[idx + 1] = lerp_channel(bg_top[1], bg_bottom[1], t, shade);
            rgba[idx + 2] = lerp_channel(bg_top[2], bg_bottom[2], t, shade);
            rgba[idx + 3] = 255;
        }
    }

    for y in 0..SIZE {
        for x in 0..SIZE {
            let edge = x.min(y).min(SIZE - 1 - x).min(SIZE - 1 - y);
            if edge < 2 {
                let alpha = 0.5 + (2 - edge) as f32 * 0.25;
                blend_pixel(&mut rgba, SIZE, x as i32, y as i32, border, alpha.min(1.0));
            }
        }
    }

    paint_ring(&mut rgba, SIZE, (27.0, 27.0), 14.0, 4.5, lens);
    paint_disc(&mut rgba, SIZE, (27.0, 27.0), 10.0, [16, 30, 47, 210]);
    paint_segment(&mut rgba, SIZE, (36.5, 36.5), (52.0, 52.0), 5.0, handle);

    paint_segment(&mut rgba, SIZE, (20.0, 23.0), (33.0, 23.0), 2.4, accent);
    paint_segment(&mut rgba, SIZE, (21.5, 28.0), (34.5, 28.0), 2.4, accent);
    paint_segment(&mut rgba, SIZE, (20.0, 33.0), (33.0, 33.0), 2.4, accent);
    paint_disc(&mut rgba, SIZE, (20.0, 23.0), 1.4, accent);
    paint_disc(&mut rgba, SIZE, (34.5, 28.0), 1.4, accent);
    paint_disc(&mut rgba, SIZE, (20.0, 33.0), 1.4, accent);

    egui::IconData {
        rgba,
        width: SIZE_U32,
        height: SIZE_U32,
    }
}

fn lerp_channel(top: u8, bottom: u8, t: f32, shade: f32) -> u8 {
    let blended = top as f32 + (bottom as f32 - top as f32) * t;
    (blended * shade).round().clamp(0.0, 255.0) as u8
}

fn blend_pixel(rgba: &mut [u8], size: usize, x: i32, y: i32, color: [u8; 4], coverage: f32) {
    if x < 0 || y < 0 || x >= size as i32 || y >= size as i32 {
        return;
    }
    let idx = ((y as usize) * size + x as usize) * 4;
    let src_a = (color[3] as f32 / 255.0) * coverage.clamp(0.0, 1.0);
    if src_a <= 0.0 {
        return;
    }

    let dst_r = rgba[idx] as f32;
    let dst_g = rgba[idx + 1] as f32;
    let dst_b = rgba[idx + 2] as f32;

    let src_r = color[0] as f32;
    let src_g = color[1] as f32;
    let src_b = color[2] as f32;

    rgba[idx] = (src_r * src_a + dst_r * (1.0 - src_a))
        .round()
        .clamp(0.0, 255.0) as u8;
    rgba[idx + 1] = (src_g * src_a + dst_g * (1.0 - src_a))
        .round()
        .clamp(0.0, 255.0) as u8;
    rgba[idx + 2] = (src_b * src_a + dst_b * (1.0 - src_a))
        .round()
        .clamp(0.0, 255.0) as u8;
    rgba[idx + 3] = 255;
}

fn paint_ring(
    rgba: &mut [u8],
    size: usize,
    center: (f32, f32),
    radius: f32,
    thickness: f32,
    color: [u8; 4],
) {
    let margin = (radius + thickness + 2.0).ceil() as i32;
    let (cx, cy) = center;
    for y in (cy as i32 - margin)..=(cy as i32 + margin) {
        for x in (cx as i32 - margin)..=(cx as i32 + margin) {
            let dist = ((x as f32 + 0.5 - cx).powi(2) + (y as f32 + 0.5 - cy).powi(2)).sqrt();
            let delta = (dist - radius).abs();
            let coverage = (thickness * 0.5 + 1.0 - delta).clamp(0.0, 1.0);
            if coverage > 0.0 {
                blend_pixel(rgba, size, x, y, color, coverage);
            }
        }
    }
}

fn paint_disc(rgba: &mut [u8], size: usize, center: (f32, f32), radius: f32, color: [u8; 4]) {
    let margin = (radius + 2.0).ceil() as i32;
    let (cx, cy) = center;
    for y in (cy as i32 - margin)..=(cy as i32 + margin) {
        for x in (cx as i32 - margin)..=(cx as i32 + margin) {
            let dist = ((x as f32 + 0.5 - cx).powi(2) + (y as f32 + 0.5 - cy).powi(2)).sqrt();
            let coverage = (radius + 1.0 - dist).clamp(0.0, 1.0);
            if coverage > 0.0 {
                blend_pixel(rgba, size, x, y, color, coverage);
            }
        }
    }
}

fn paint_segment(
    rgba: &mut [u8],
    size: usize,
    from: (f32, f32),
    to: (f32, f32),
    thickness: f32,
    color: [u8; 4],
) {
    let min_x = from.0.min(to.0).floor() as i32 - (thickness.ceil() as i32) - 2;
    let max_x = from.0.max(to.0).ceil() as i32 + (thickness.ceil() as i32) + 2;
    let min_y = from.1.min(to.1).floor() as i32 - (thickness.ceil() as i32) - 2;
    let max_y = from.1.max(to.1).ceil() as i32 + (thickness.ceil() as i32) + 2;

    for y in min_y..=max_y {
        for x in min_x..=max_x {
            let dist = point_segment_distance((x as f32 + 0.5, y as f32 + 0.5), from, to);
            let coverage = (thickness * 0.5 + 1.0 - dist).clamp(0.0, 1.0);
            if coverage > 0.0 {
                blend_pixel(rgba, size, x, y, color, coverage);
            }
        }
    }
}

fn point_segment_distance(point: (f32, f32), from: (f32, f32), to: (f32, f32)) -> f32 {
    let vx = to.0 - from.0;
    let vy = to.1 - from.1;
    let wx = point.0 - from.0;
    let wy = point.1 - from.1;
    let segment_len_sq = vx * vx + vy * vy;
    if segment_len_sq <= f32::EPSILON {
        return ((point.0 - from.0).powi(2) + (point.1 - from.1).powi(2)).sqrt();
    }
    let t = ((wx * vx + wy * vy) / segment_len_sq).clamp(0.0, 1.0);
    let proj_x = from.0 + t * vx;
    let proj_y = from.1 + t * vy;
    ((point.0 - proj_x).powi(2) + (point.1 - proj_y).powi(2)).sqrt()
}
