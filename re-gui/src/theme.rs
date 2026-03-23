use eframe::egui;

#[derive(PartialEq, Clone, Copy)]
pub(crate) enum ThemeMode {
    Light,
    Dark,
    Solarized,
}

/// Colors used for syntax highlighting in disassembly and graph views
#[allow(dead_code)]
pub(crate) struct SyntaxColors {
    pub(crate) address: egui::Color32,
    pub(crate) mnemonic: egui::Color32,
    pub(crate) register: egui::Color32,
    pub(crate) number: egui::Color32,
    pub(crate) string: egui::Color32,
    pub(crate) comment: egui::Color32,
    pub(crate) keyword: egui::Color32, // call, ret, jmp etc.
    pub(crate) simd: egui::Color32,
    pub(crate) bytes: egui::Color32,
    pub(crate) label: egui::Color32,
    pub(crate) text: egui::Color32,
    pub(crate) text_dim: egui::Color32,

    // Graph edge colors
    pub(crate) edge_true: egui::Color32,
    pub(crate) edge_false: egui::Color32,
    pub(crate) edge_unconditional: egui::Color32,
    pub(crate) edge_fallthrough: egui::Color32,
    pub(crate) edge_back: egui::Color32,

    // UI element colors
    pub(crate) link: egui::Color32,
    pub(crate) block_bg: egui::Color32,
    pub(crate) block_border: egui::Color32,
    pub(crate) nav_band_bg: egui::Color32,
    pub(crate) nav_band_exec: egui::Color32,
    pub(crate) nav_band_data: egui::Color32,
    pub(crate) func_badge_bg: egui::Color32,
    pub(crate) bookmark_badge_bg: egui::Color32,
    pub(crate) selection_bg: egui::Color32,
    pub(crate) ascii_text: egui::Color32,

    // Status bar
    pub(crate) status_bar_bg: egui::Color32,

    // Navigation band layers
    pub(crate) nav_band_func_user: egui::Color32,
    pub(crate) nav_band_func_lib: egui::Color32,
    pub(crate) nav_band_string: egui::Color32,
    pub(crate) nav_band_unexplored: egui::Color32,
}

impl SyntaxColors {
    pub(crate) fn for_theme(mode: ThemeMode) -> Self {
        match mode {
            ThemeMode::Light => Self::light(),
            ThemeMode::Dark => Self::dark(),
            ThemeMode::Solarized => Self::solarized(),
        }
    }

    fn light() -> Self {
        Self {
            address: egui::Color32::GRAY,
            mnemonic: egui::Color32::from_rgb(0, 0, 180),
            register: egui::Color32::from_rgb(140, 0, 140),
            number: egui::Color32::from_rgb(0, 128, 0),
            string: egui::Color32::from_rgb(163, 21, 21),
            comment: egui::Color32::from_rgb(0, 128, 0),
            keyword: egui::Color32::from_rgb(0, 0, 255),
            simd: egui::Color32::from_rgb(255, 140, 0),
            bytes: egui::Color32::LIGHT_GRAY,
            label: egui::Color32::from_rgb(160, 80, 0),
            text: egui::Color32::BLACK,
            text_dim: egui::Color32::GRAY,

            edge_true: egui::Color32::from_rgb(0, 180, 0),
            edge_false: egui::Color32::from_rgb(200, 0, 0),
            edge_unconditional: egui::Color32::from_rgb(0, 120, 200),
            edge_fallthrough: egui::Color32::from_rgb(150, 150, 150),
            edge_back: egui::Color32::from_rgb(200, 80, 200),

            link: egui::Color32::from_rgb(0, 0, 200),
            block_bg: egui::Color32::from_rgb(248, 248, 248),
            block_border: egui::Color32::from_rgb(100, 100, 100),
            nav_band_bg: egui::Color32::from_rgb(200, 200, 200),
            nav_band_exec: egui::Color32::from_rgb(0, 160, 255),
            nav_band_data: egui::Color32::from_rgb(180, 180, 180),
            func_badge_bg: egui::Color32::from_rgb(180, 220, 255),
            bookmark_badge_bg: egui::Color32::from_rgb(255, 220, 180),
            selection_bg: egui::Color32::from_rgba_unmultiplied(0, 0, 0, 20),
            ascii_text: egui::Color32::from_rgb(0, 100, 0),

            status_bar_bg: egui::Color32::from_rgb(220, 220, 220),

            nav_band_func_user: egui::Color32::from_rgb(0, 200, 255),
            nav_band_func_lib: egui::Color32::from_rgb(0, 0, 255),
            nav_band_string: egui::Color32::from_rgb(180, 180, 100),
            nav_band_unexplored: egui::Color32::from_rgb(180, 180, 180),
        }
    }

    fn dark() -> Self {
        Self {
            address: egui::Color32::from_rgb(128, 128, 128),
            mnemonic: egui::Color32::from_rgb(86, 156, 214),
            register: egui::Color32::from_rgb(190, 120, 220),
            number: egui::Color32::from_rgb(181, 206, 168),
            string: egui::Color32::from_rgb(214, 157, 133),
            comment: egui::Color32::from_rgb(106, 153, 85),
            keyword: egui::Color32::from_rgb(197, 134, 192),
            simd: egui::Color32::from_rgb(220, 170, 80),
            bytes: egui::Color32::from_rgb(80, 80, 80),
            label: egui::Color32::from_rgb(220, 220, 170),
            text: egui::Color32::from_rgb(212, 212, 212),
            text_dim: egui::Color32::from_rgb(128, 128, 128),

            edge_true: egui::Color32::from_rgb(80, 220, 80),
            edge_false: egui::Color32::from_rgb(220, 60, 60),
            edge_unconditional: egui::Color32::from_rgb(80, 160, 240),
            edge_fallthrough: egui::Color32::from_rgb(120, 120, 120),
            edge_back: egui::Color32::from_rgb(200, 120, 220),

            link: egui::Color32::from_rgb(80, 160, 240),
            block_bg: egui::Color32::from_rgb(40, 40, 40),
            block_border: egui::Color32::from_rgb(80, 80, 80),
            nav_band_bg: egui::Color32::from_rgb(50, 50, 50),
            nav_band_exec: egui::Color32::from_rgb(40, 120, 200),
            nav_band_data: egui::Color32::from_rgb(70, 70, 70),
            func_badge_bg: egui::Color32::from_rgb(40, 70, 100),
            bookmark_badge_bg: egui::Color32::from_rgb(100, 80, 40),
            selection_bg: egui::Color32::from_rgba_unmultiplied(255, 255, 255, 20),
            ascii_text: egui::Color32::from_rgb(80, 200, 80),

            status_bar_bg: egui::Color32::from_rgb(25, 25, 25),

            nav_band_func_user: egui::Color32::from_rgb(0, 160, 200),
            nav_band_func_lib: egui::Color32::from_rgb(40, 40, 200),
            nav_band_string: egui::Color32::from_rgb(180, 180, 100),
            nav_band_unexplored: egui::Color32::from_rgb(60, 60, 60),
        }
    }

    /// Solarized Dark palette (Ethan Schoonover)
    fn solarized() -> Self {
        // Base tones
        let base03 = egui::Color32::from_rgb(0, 43, 54);
        let base02 = egui::Color32::from_rgb(7, 54, 66);
        let base01 = egui::Color32::from_rgb(88, 110, 117);
        let base0 = egui::Color32::from_rgb(131, 148, 150);
        let _base1 = egui::Color32::from_rgb(147, 161, 161);
        // Accent colors
        let yellow = egui::Color32::from_rgb(181, 137, 0);
        let orange = egui::Color32::from_rgb(203, 75, 22);
        let red = egui::Color32::from_rgb(220, 50, 47);
        let magenta = egui::Color32::from_rgb(211, 54, 130);
        let violet = egui::Color32::from_rgb(108, 113, 196);
        let blue = egui::Color32::from_rgb(38, 139, 210);
        let cyan = egui::Color32::from_rgb(42, 161, 152);
        let green = egui::Color32::from_rgb(133, 153, 0);

        Self {
            address: base01,
            mnemonic: blue,
            register: violet,
            number: cyan,
            string: orange,
            comment: base01,
            keyword: magenta,
            simd: yellow,
            bytes: base02,
            label: yellow,
            text: base0,
            text_dim: base01,

            edge_true: green,
            edge_false: red,
            edge_unconditional: blue,
            edge_fallthrough: base01,
            edge_back: magenta,

            link: blue,
            block_bg: base03,
            block_border: base01,
            nav_band_bg: base02,
            nav_band_exec: blue,
            nav_band_data: base02,
            func_badge_bg: egui::Color32::from_rgb(7, 70, 90),
            bookmark_badge_bg: egui::Color32::from_rgb(90, 70, 7),
            selection_bg: egui::Color32::from_rgba_unmultiplied(131, 148, 150, 30),
            ascii_text: green,

            status_bar_bg: base03,

            nav_band_func_user: cyan,
            nav_band_func_lib: violet,
            nav_band_string: yellow,
            nav_band_unexplored: base02,
        }
    }
}

pub(crate) fn apply_theme(ctx: &egui::Context, mode: ThemeMode) {
    match mode {
        ThemeMode::Light => {
            let mut visuals = egui::Visuals::light();
            visuals.panel_fill = egui::Color32::from_rgb(240, 240, 240);
            visuals.window_fill = egui::Color32::from_rgb(255, 255, 255);
            visuals.widgets.noninteractive.bg_fill = egui::Color32::from_rgb(240, 240, 240);
            ctx.set_visuals(visuals);
        }
        ThemeMode::Dark => {
            let mut visuals = egui::Visuals::dark();
            visuals.panel_fill = egui::Color32::from_rgb(30, 30, 30);
            visuals.window_fill = egui::Color32::from_rgb(35, 35, 35);
            visuals.widgets.noninteractive.bg_fill = egui::Color32::from_rgb(30, 30, 30);
            ctx.set_visuals(visuals);
        }
        ThemeMode::Solarized => {
            let mut visuals = egui::Visuals::dark();
            visuals.panel_fill = egui::Color32::from_rgb(0, 43, 54);
            visuals.window_fill = egui::Color32::from_rgb(7, 54, 66);
            visuals.widgets.noninteractive.bg_fill = egui::Color32::from_rgb(0, 43, 54);
            visuals.widgets.noninteractive.fg_stroke =
                egui::Stroke::new(1.0, egui::Color32::from_rgb(131, 148, 150));
            visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(7, 54, 66);
            visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(7, 70, 90);
            visuals.widgets.active.bg_fill = egui::Color32::from_rgb(7, 80, 100);
            visuals.extreme_bg_color = egui::Color32::from_rgb(0, 43, 54);
            visuals.faint_bg_color = egui::Color32::from_rgb(7, 54, 66);
            ctx.set_visuals(visuals);
        }
    }
}
