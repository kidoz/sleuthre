use eframe::egui;
use re_core::types::{CompoundType, PrimitiveType, TypeRef};

use crate::app::SleuthreApp;

impl SleuthreApp {
    pub(crate) fn show_structures(&mut self, ui: &mut egui::Ui) {
        let project = match &self.project {
            Some(p) => p,
            None => {
                ui.label("No binary loaded");
                return;
            }
        };

        ui.horizontal(|ui| {
            ui.label("Filter:");
            ui.text_edit_singleline(&mut self.structure_filter);
            ui.label(format!("{} types", project.types.types.len()));
            ui.add_space(8.0);
            if ui.button("+ New Struct").clicked() {
                self.create_struct_active = true;
                self.new_struct_name = "NewStruct".into();
            }
            if ui.button("+ New Enum").clicked() {
                self.create_enum_active = true;
                self.new_enum_name = "NewEnum".into();
                self.new_enum_variants.clear();
                self.new_enum_variants.push(("VALUE_0".into(), "0".into()));
            }
        });
        ui.separator();

        if project.types.types.is_empty() {
            ui.label("No user-defined types. Click '+ New Struct' or '+ New Enum' to create one.");
            return;
        }

        // Collect actions to apply after iteration (avoid borrow issues)
        let mut delete_type = None;
        #[allow(unused_mut)]
        let mut rename_type: Option<(String, String)> = None;
        let mut delete_field: Option<(String, usize)> = None;
        #[allow(unused_mut)]
        let mut edit_field: Option<(String, usize, String, String, String)> = None;

        egui::ScrollArea::vertical().show(ui, |ui| {
            let type_names: Vec<String> = project.types.types.keys().cloned().collect();
            for type_name in &type_names {
                let ty = match project.types.types.get(type_name) {
                    Some(t) => t,
                    None => continue,
                };

                if !self.structure_filter.is_empty()
                    && !ty
                        .name()
                        .to_lowercase()
                        .contains(&self.structure_filter.to_lowercase())
                {
                    continue;
                }

                let header = format!(
                    "{} {} (size: {} bytes)",
                    ty.kind_name(),
                    ty.name(),
                    ty.size(project.arch)
                );

                egui::CollapsingHeader::new(
                    egui::RichText::new(&header)
                        .monospace()
                        .color(egui::Color32::from_rgb(0, 80, 160)),
                )
                .id_salt(format!("struct_{}", type_name))
                .show(ui, |ui| {
                    // Action buttons row
                    ui.horizontal(|ui| {
                        if ui.small_button("Delete Type").clicked() {
                            delete_type = Some(type_name.clone());
                        }
                        if ui.small_button("Rename Type").clicked() {
                            self.rename_type_active = true;
                            self.rename_type_old = type_name.clone();
                            self.rename_type_new = type_name.clone();
                        }
                    });
                    ui.separator();

                    // Class / inheritance row (struct only). Read-only here; editable via
                    // the class editor dialog opened from the "Edit Class..." button.
                    if matches!(ty, CompoundType::Struct { .. })
                        && let Some(ref project) = self.project
                        && let Some(info) = project.types.classes.get(type_name)
                    {
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new("class:")
                                    .color(egui::Color32::from_rgb(180, 220, 255))
                                    .size(10.0),
                            );
                            if let Some(ref base) = info.base {
                                ui.label(
                                    egui::RichText::new(format!("extends {}", base))
                                        .size(10.0)
                                        .color(egui::Color32::LIGHT_BLUE),
                                );
                            }
                            if let Some(ref vt) = info.vtable_label {
                                ui.label(
                                    egui::RichText::new(format!("vtable: {}", vt))
                                        .size(10.0)
                                        .color(egui::Color32::from_rgb(230, 200, 140)),
                                );
                            }
                            if let Some(addr) = info.vtable_address {
                                ui.label(
                                    egui::RichText::new(format!("@ 0x{:X}", addr))
                                        .size(10.0)
                                        .monospace(),
                                );
                            }
                        });
                    }
                    if matches!(ty, CompoundType::Struct { .. })
                        && ui.small_button("Edit Class...").clicked()
                    {
                        self.class_edit_active = true;
                        self.class_edit_target = type_name.clone();
                        if let Some(ref project) = self.project
                            && let Some(info) = project.types.classes.get(type_name)
                        {
                            self.class_edit_base = info.base.clone().unwrap_or_default();
                            self.class_edit_vtable_label =
                                info.vtable_label.clone().unwrap_or_default();
                            self.class_edit_vtable_addr = info
                                .vtable_address
                                .map(|a| format!("0x{:X}", a))
                                .unwrap_or_default();
                        } else {
                            self.class_edit_base.clear();
                            self.class_edit_vtable_label.clear();
                            self.class_edit_vtable_addr.clear();
                        }
                    }

                    match ty {
                        CompoundType::Struct { fields, name, .. }
                        | CompoundType::Union { fields, name, .. } => {
                            // If class has a base, show inherited fields as read-only header.
                            if let CompoundType::Struct { .. } = ty
                                && let Some(ref project) = self.project
                                && let Some(info) = project.types.classes.get(name)
                                && let Some(ref base_name) = info.base
                                && let Some(CompoundType::Struct {
                                    fields: base_fields,
                                    ..
                                }) = project.types.types.get(base_name)
                            {
                                ui.label(
                                    egui::RichText::new(format!("// inherited from {}", base_name))
                                        .size(10.0)
                                        .color(egui::Color32::DARK_GRAY),
                                );
                                for field in base_fields {
                                    ui.monospace(
                                        egui::RichText::new(format!(
                                            "  +{:#04X}  {}  {}",
                                            field.offset,
                                            field.type_ref.display_name(),
                                            field.name
                                        ))
                                        .color(egui::Color32::DARK_GRAY),
                                    );
                                }
                                ui.separator();
                            }
                            for (idx, field) in fields.iter().enumerate() {
                                ui.horizontal(|ui| {
                                    ui.monospace(format!(
                                        "  +{:#04X}  {}  {}",
                                        field.offset,
                                        field.type_ref.display_name(),
                                        field.name
                                    ));
                                    if ui.small_button("Edit").clicked() {
                                        self.edit_field_active = true;
                                        self.edit_field_struct = name.clone();
                                        self.edit_field_index = idx;
                                        self.edit_field_name = field.name.clone();
                                        self.edit_field_offset = format!("{:#X}", field.offset);
                                        self.edit_field_type = field.type_ref.display_name();
                                    }
                                    if ui.small_button("x").clicked() {
                                        delete_field = Some((name.clone(), idx));
                                    }
                                });
                            }
                            if ui.button("+ Add Field").clicked() {
                                self.editing_struct = Some(name.clone());
                                self.new_field_name = format!("field_{}", fields.len());
                                self.new_field_offset = fields
                                    .last()
                                    .map(|f| format!("{:#X}", f.offset + 4))
                                    .unwrap_or("0x0".into());
                                self.new_field_type = "int32_t".into();
                            }
                        }
                        CompoundType::Enum { variants, .. } => {
                            for (ename, val) in variants {
                                ui.monospace(format!("  {} = {}", ename, val));
                            }
                        }
                        CompoundType::Typedef { target, .. } => {
                            ui.monospace(format!("  -> {}", target.display_name()));
                        }
                    }
                });
            }
        });

        // Apply deferred mutations
        if let Some(name) = delete_type
            && let Some(ref mut project) = self.project
        {
            project.types.remove_type(&name);
            project.decompilation_cache.clear();
        }
        if let Some((old, new)) = rename_type
            && let Some(ref mut project) = self.project
            && let Some(mut ty) = project.types.remove_type(&old)
        {
            match &mut ty {
                CompoundType::Struct { name, .. }
                | CompoundType::Union { name, .. }
                | CompoundType::Enum { name, .. }
                | CompoundType::Typedef { name, .. } => {
                    *name = new;
                }
            }
            project.types.add_type(ty);
            project.decompilation_cache.clear();
        }
        if let Some((struct_name, field_idx)) = delete_field
            && let Some(ref mut project) = self.project
        {
            if let Some(CompoundType::Struct { fields, .. } | CompoundType::Union { fields, .. }) =
                project.types.types.get_mut(&struct_name)
                && field_idx < fields.len()
            {
                fields.remove(field_idx);
            }
            project.decompilation_cache.clear();
        }
        if let Some((struct_name, field_idx, name, offset_str, type_str)) = edit_field
            && let Some(ref mut project) = self.project
        {
            if let Some(CompoundType::Struct { fields, .. } | CompoundType::Union { fields, .. }) =
                project.types.types.get_mut(&struct_name)
                && field_idx < fields.len()
            {
                fields[field_idx].name = name;
                if let Some(offset) = parse_hex_or_dec(&offset_str) {
                    fields[field_idx].offset = offset;
                }
                fields[field_idx].type_ref = parse_type_str(&type_str);
            }
            project.decompilation_cache.clear();
        }

        // Edit Field dialog
        self.show_edit_field_dialog(ui.ctx());
        // Rename Type dialog
        self.show_rename_type_dialog(ui.ctx());
        // New Enum dialog
        self.show_create_enum_dialog(ui.ctx());
    }

    fn show_edit_field_dialog(&mut self, ctx: &egui::Context) {
        if !self.edit_field_active {
            return;
        }
        egui::Window::new("Edit Field")
            .collapsible(false)
            .show(ctx, |ui| {
                ui.label(format!("Struct: {}", self.edit_field_struct));
                ui.horizontal(|ui| {
                    ui.label("Name:");
                    ui.text_edit_singleline(&mut self.edit_field_name);
                });
                ui.horizontal(|ui| {
                    ui.label("Offset:");
                    ui.text_edit_singleline(&mut self.edit_field_offset);
                });
                ui.horizontal(|ui| {
                    ui.label("Type:");
                    ui.text_edit_singleline(&mut self.edit_field_type);
                });
                // Type suggestions
                ui.horizontal(|ui| {
                    for ty in COMMON_TYPES {
                        if ui.small_button(*ty).clicked() {
                            self.edit_field_type = ty.to_string();
                        }
                    }
                });
                ui.horizontal(|ui| {
                    if ui.button("Save").clicked() {
                        if let Some(ref mut project) = self.project {
                            if let Some(
                                CompoundType::Struct { fields, .. }
                                | CompoundType::Union { fields, .. },
                            ) = project.types.types.get_mut(&self.edit_field_struct)
                                && self.edit_field_index < fields.len()
                            {
                                fields[self.edit_field_index].name = self.edit_field_name.clone();
                                if let Some(offset) = parse_hex_or_dec(&self.edit_field_offset) {
                                    fields[self.edit_field_index].offset = offset;
                                }
                                fields[self.edit_field_index].type_ref =
                                    parse_type_str(&self.edit_field_type);
                            }
                            project.decompilation_cache.clear();
                        }
                        self.edit_field_active = false;
                    }
                    if ui.button("Cancel").clicked() {
                        self.edit_field_active = false;
                    }
                });
            });
    }

    fn show_rename_type_dialog(&mut self, ctx: &egui::Context) {
        if !self.rename_type_active {
            return;
        }
        egui::Window::new("Rename Type")
            .collapsible(false)
            .show(ctx, |ui| {
                ui.label(format!("Current name: {}", self.rename_type_old));
                ui.horizontal(|ui| {
                    ui.label("New name:");
                    ui.text_edit_singleline(&mut self.rename_type_new);
                });
                ui.horizontal(|ui| {
                    if ui.button("Rename").clicked() {
                        let old = self.rename_type_old.clone();
                        let new = self.rename_type_new.clone();
                        if !new.is_empty()
                            && old != new
                            && let Some(ref mut project) = self.project
                            && let Some(mut ty) = project.types.remove_type(&old)
                        {
                            match &mut ty {
                                CompoundType::Struct { name, .. }
                                | CompoundType::Union { name, .. }
                                | CompoundType::Enum { name, .. }
                                | CompoundType::Typedef { name, .. } => {
                                    *name = new;
                                }
                            }
                            project.types.add_type(ty);
                            project.decompilation_cache.clear();
                        }
                        self.rename_type_active = false;
                    }
                    if ui.button("Cancel").clicked() {
                        self.rename_type_active = false;
                    }
                });
            });
    }

    fn show_create_enum_dialog(&mut self, ctx: &egui::Context) {
        if !self.create_enum_active {
            return;
        }
        egui::Window::new("New Enum")
            .collapsible(false)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Name:");
                    ui.text_edit_singleline(&mut self.new_enum_name);
                });
                ui.separator();
                ui.label("Variants:");
                let mut remove_idx = None;
                for (i, (name, val)) in self.new_enum_variants.iter_mut().enumerate() {
                    ui.horizontal(|ui| {
                        ui.text_edit_singleline(name);
                        ui.label("=");
                        ui.add(egui::TextEdit::singleline(val).desired_width(60.0));
                        if ui.small_button("x").clicked() {
                            remove_idx = Some(i);
                        }
                    });
                }
                if let Some(idx) = remove_idx {
                    self.new_enum_variants.remove(idx);
                }
                if ui.button("+ Add Variant").clicked() {
                    let next_val = self.new_enum_variants.len();
                    self.new_enum_variants
                        .push((format!("VALUE_{}", next_val), format!("{}", next_val)));
                }
                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button("Create").clicked() {
                        let variants: Vec<(String, i64)> = self
                            .new_enum_variants
                            .iter()
                            .filter_map(|(n, v)| v.parse::<i64>().ok().map(|val| (n.clone(), val)))
                            .collect();
                        if !self.new_enum_name.is_empty() {
                            let ty = CompoundType::Enum {
                                name: self.new_enum_name.clone(),
                                variants,
                                size: 4,
                            };
                            if let Some(ref mut project) = self.project {
                                project.types.add_type(ty);
                            }
                        }
                        self.create_enum_active = false;
                    }
                    if ui.button("Cancel").clicked() {
                        self.create_enum_active = false;
                    }
                });
            });
    }
}

const COMMON_TYPES: &[&str] = &[
    "uint8_t", "int8_t", "uint16_t", "int16_t", "uint32_t", "int32_t", "uint64_t", "int64_t",
    "float", "double", "void*", "char*",
];

fn parse_type_str(s: &str) -> TypeRef {
    let s = s.trim();
    if let Some(stripped) = s.strip_suffix('*') {
        let inner = parse_type_str(stripped);
        return TypeRef::Pointer(Box::new(inner));
    }
    match s {
        "void" => TypeRef::Primitive(PrimitiveType::Void),
        "bool" => TypeRef::Primitive(PrimitiveType::Bool),
        "char" => TypeRef::Primitive(PrimitiveType::Char),
        "uint8_t" | "u8" | "unsigned char" | "BYTE" => TypeRef::Primitive(PrimitiveType::U8),
        "int8_t" | "i8" | "signed char" => TypeRef::Primitive(PrimitiveType::I8),
        "uint16_t" | "u16" | "unsigned short" | "WORD" => TypeRef::Primitive(PrimitiveType::U16),
        "int16_t" | "i16" | "short" => TypeRef::Primitive(PrimitiveType::I16),
        "uint32_t" | "u32" | "unsigned int" | "DWORD" => TypeRef::Primitive(PrimitiveType::U32),
        "int32_t" | "i32" | "int" => TypeRef::Primitive(PrimitiveType::I32),
        "uint64_t" | "u64" | "unsigned long long" | "QWORD" => {
            TypeRef::Primitive(PrimitiveType::U64)
        }
        "int64_t" | "i64" | "long long" => TypeRef::Primitive(PrimitiveType::I64),
        "float" | "f32" => TypeRef::Primitive(PrimitiveType::F32),
        "double" | "f64" => TypeRef::Primitive(PrimitiveType::F64),
        "size_t" | "usize" => TypeRef::Primitive(PrimitiveType::USize),
        _ => TypeRef::Named(s.to_string()),
    }
}

fn parse_hex_or_dec(s: &str) -> Option<usize> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        usize::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
}
