const std = @import("std");

pub const Heap = enum {
    string,
    guid,
    blob,

    const properties: std.enums.EnumFieldStruct(Heap, u8, null) = .{
        .string = 0x01,
        .guid = 0x02,
        .blob = 0x04,
    };

    pub fn flagBit(heap: Heap) u8 {
        return @field(properties, @tagName(heap));
    }
};

pub const Table = enum {
    module,
    type_ref,
    type_def,
    field,
    method_def,
    param,
    interface_impl,
    member_ref,
    constant,
    custom_attribute,
    field_marshal,
    decl_security,
    class_layout,
    field_layout,
    stand_alone_sig,
    event_map,
    event,
    property_map,
    property,
    method_semantics,
    method_impl,
    module_ref,
    type_spec,
    impl_map,
    field_rva,
    assembly,
    assembly_processor,
    assembly_os,
    assembly_ref,
    assembly_ref_processor,
    assembly_ref_os,
    file,
    exported_type,
    manifest_resource,
    nested_class,
    generic_param,
    method_spec,
    generic_param_constraint,

    const properties: std.enums.EnumFieldStruct(Table, struct { u6, type }, null) = .{
        .module = .{ 0x00, ModuleColumn },
        .type_ref = .{ 0x01, TypeRefColumn },
        .type_def = .{ 0x02, TypeDefColumn },
        .field = .{ 0x04, FieldColumn },
        .method_def = .{ 0x06, MethodDefColumn },
        .param = .{ 0x08, ParamColumn },
        .interface_impl = .{ 0x09, InterfaceImplColumn },
        .member_ref = .{ 0x0A, MemberRefColumn },
        .constant = .{ 0x0B, ConstantColumn },
        .custom_attribute = .{ 0x0C, CustomAttributeColumn },
        .field_marshal = .{ 0x0D, FieldMarshalColumn },
        .decl_security = .{ 0x0E, DeclSecurityColumn },
        .class_layout = .{ 0x0F, ClassLayoutColumn },
        .field_layout = .{ 0x10, FieldLayoutColumn },
        .stand_alone_sig = .{ 0x11, StandAloneSigColumn },
        .event_map = .{ 0x12, EventMapColumn },
        .event = .{ 0x14, EventColumn },
        .property_map = .{ 0x15, PropertyMapColumn },
        .property = .{ 0x17, PropertyColumn },
        .method_semantics = .{ 0x18, MethodSemanticsColumn },
        .method_impl = .{ 0x19, MethodImplColumn },
        .module_ref = .{ 0x1A, ModuleRefColumn },
        .type_spec = .{ 0x1B, TypeSpecColumn },
        .impl_map = .{ 0x1C, ImplMapColumn },
        .field_rva = .{ 0x1D, FieldRvaColumn },
        .assembly = .{ 0x20, AssemblyColumn },
        .assembly_processor = .{ 0x21, AssemblyProcessorColumn },
        .assembly_os = .{ 0x22, AssemblyOsColumn },
        .assembly_ref = .{ 0x23, AssemblyRefColumn },
        .assembly_ref_processor = .{ 0x24, AssemblyRefProcessorColumn },
        .assembly_ref_os = .{ 0x25, AssemblyRefOsColumn },
        .file = .{ 0x26, FileColumn },
        .exported_type = .{ 0x27, ExportedTypeColumn },
        .manifest_resource = .{ 0x28, ManifestResourceColumn },
        .nested_class = .{ 0x29, NestedClassColumn },
        .generic_param = .{ 0x2A, GenericParamColumn },
        .method_spec = .{ 0x2B, MethodSpecColumn },
        .generic_param_constraint = .{ 0x2C, GenericParamConstraintColumn },
    };

    pub fn id(comptime table: Table) u6 {
        return @field(properties, @tagName(table))[0];
    }

    pub fn Column(table: Table) type {
        return @field(properties, @tagName(table))[1];
    }

    pub fn validBit(comptime table: Table) u64 {
        return @as(u64, 1) << table.id();
    }

    pub fn Row(table: Table) type {
        const TableColumn = table.Column();
        const table_columns = std.enums.values(TableColumn);
        var row_struct_fields: [table_columns.len]std.builtin.Type.StructField = undefined;

        for (&row_struct_fields, table_columns) |*row_struct_field, table_column| {
            const RowFieldType = table_column.dataType().Type();

            row_struct_field.* = .{
                .name = @tagName(table_column),
                .type = RowFieldType,
                .default_value_ptr = null,
                .is_comptime = false,
                .alignment = @alignOf(RowFieldType),
            };
        }
        return @Type(.{ .@"struct" = .{
            .layout = .auto,
            .fields = &row_struct_fields,
            .decls = &.{},
            .is_tuple = false,
        } });
    }
};

pub const ModuleColumn = enum {
    generation,
    name,
    mvid,
    enc_id,
    enc_base_id,

    const properties: std.enums.EnumFieldStruct(ModuleColumn, DataType, null) = .{
        .generation = .{ .int = 2 },
        .name = .{ .index = .{ .heap = .string } },
        .mvid = .{ .index = .{ .heap = .guid } },
        .enc_id = .{ .index = .{ .heap = .guid } },
        .enc_base_id = .{ .index = .{ .heap = .guid } },
    };

    pub fn dataType(column: ModuleColumn) DataType {
        return @field(properties, @tagName(column));
    }
};

pub const TypeRefColumn = enum {
    resolution_scope,
    type_name,
    type_namespace,

    const properties: std.enums.EnumFieldStruct(TypeRefColumn, DataType, null) = .{
        .resolution_scope = .{ .index = .{ .coded = .resolution_scope } },
        .type_name = .{ .index = .{ .heap = .string } },
        .type_namespace = .{ .index = .{ .heap = .string } },
    };

    pub fn dataType(column: TypeRefColumn) DataType {
        return @field(properties, @tagName(column));
    }
};

pub const TypeDefColumn = enum {
    flags,
    type_name,
    type_namespace,
    extends,
    field_list,
    method_list,

    const properties: std.enums.EnumFieldStruct(TypeDefColumn, DataType, null) = .{
        .flags = .{ .int = 4 },
        .type_name = .{ .index = .{ .heap = .string } },
        .type_namespace = .{ .index = .{ .heap = .string } },
        .extends = .{ .index = .{ .coded = .type_def_or_ref } },
        .field_list = .{ .index = .{ .table = .field } },
        .method_list = .{ .index = .{ .table = .method_def } },
    };

    pub fn dataType(column: TypeDefColumn) DataType {
        return @field(properties, @tagName(column));
    }
};

pub const FieldColumn = enum {
    flags,
    name,
    signature,

    const properties: std.enums.EnumFieldStruct(FieldColumn, DataType, null) = .{
        .flags = .{ .int = 2 },
        .name = .{ .index = .{ .heap = .string } },
        .signature = .{ .index = .{ .heap = .blob } },
    };

    pub fn dataType(column: FieldColumn) DataType {
        return @field(properties, @tagName(column));
    }
};

pub const MethodDefColumn = enum {
    rva,
    impl_flags,
    flags,
    name,
    signature,
    param_list,

    const properties: std.enums.EnumFieldStruct(MethodDefColumn, DataType, null) = .{
        .rva = .{ .int = 4 },
        .impl_flags = .{ .int = 2 },
        .flags = .{ .int = 2 },
        .name = .{ .index = .{ .heap = .string } },
        .signature = .{ .index = .{ .heap = .blob } },
        .param_list = .{ .index = .{ .table = .param } },
    };

    pub fn dataType(column: MethodDefColumn) DataType {
        return @field(properties, @tagName(column));
    }
};

pub const ParamColumn = enum {
    flags,
    sequence,
    name,

    const properties: std.enums.EnumFieldStruct(ParamColumn, DataType, null) = .{
        .flags = .{ .int = 2 },
        .sequence = .{ .int = 2 },
        .name = .{ .index = .{ .heap = .string } },
    };

    pub fn dataType(column: ParamColumn) DataType {
        return @field(properties, @tagName(column));
    }
};

pub const InterfaceImplColumn = enum {
    class,
    interface,

    const properties: std.enums.EnumFieldStruct(InterfaceImplColumn, DataType, null) = .{
        .class = .{ .index = .{ .table = .type_def } },
        .interface = .{ .index = .{ .coded = .type_def_or_ref } },
    };

    pub fn dataType(column: InterfaceImplColumn) DataType {
        return @field(properties, @tagName(column));
    }
};

pub const MemberRefColumn = enum {
    class,
    name,
    signature,

    const properties: std.enums.EnumFieldStruct(MemberRefColumn, DataType, null) = .{
        .class = .{ .index = .{ .coded = .member_ref_parent } },
        .name = .{ .index = .{ .heap = .string } },
        .signature = .{ .index = .{ .heap = .blob } },
    };

    pub fn dataType(column: MemberRefColumn) DataType {
        return @field(properties, @tagName(column));
    }
};

pub const ConstantColumn = enum {
    type,
    parent,
    value,

    const properties: std.enums.EnumFieldStruct(ConstantColumn, DataType, null) = .{
        .type = .{ .int = 2 },
        .parent = .{ .index = .{ .coded = .has_constant } },
        .value = .{ .index = .{ .heap = .blob } },
    };

    pub fn dataType(column: ConstantColumn) DataType {
        return @field(properties, @tagName(column));
    }
};

pub const CustomAttributeColumn = enum {
    parent,
    type,
    value,

    const properties: std.enums.EnumFieldStruct(CustomAttributeColumn, DataType, null) = .{
        .parent = .{ .index = .{ .coded = .has_custom_attribute } },
        .type = .{ .index = .{ .coded = .custom_attribute_type } },
        .value = .{ .index = .{ .heap = .blob } },
    };

    pub fn dataType(column: CustomAttributeColumn) DataType {
        return @field(properties, @tagName(column));
    }
};

pub const FieldMarshalColumn = enum {
    parent,
    native_type,

    const properties: std.enums.EnumFieldStruct(FieldMarshalColumn, DataType, null) = .{
        .parent = .{ .index = .{ .coded = .has_field_marshal } },
        .native_type = .{ .index = .{ .heap = .blob } },
    };

    pub fn dataType(column: FieldMarshalColumn) DataType {
        return @field(properties, @tagName(column));
    }
};

pub const DeclSecurityColumn = enum {
    action,
    parent,
    permission_set,

    const properties: std.enums.EnumFieldStruct(DeclSecurityColumn, DataType, null) = .{
        .action = .{ .int = 2 },
        .parent = .{ .index = .{ .coded = .has_decl_security } },
        .permission_set = .{ .index = .{ .heap = .blob } },
    };

    pub fn dataType(column: DeclSecurityColumn) DataType {
        return @field(properties, @tagName(column));
    }
};

pub const ClassLayoutColumn = enum {
    packing_size,
    class_size,
    parent,

    const properties: std.enums.EnumFieldStruct(ClassLayoutColumn, DataType, null) = .{
        .packing_size = .{ .int = 2 },
        .class_size = .{ .int = 4 },
        .parent = .{ .index = .{ .table = .type_def } },
    };

    pub fn dataType(column: ClassLayoutColumn) DataType {
        return @field(properties, @tagName(column));
    }
};

pub const FieldLayoutColumn = enum {
    offset,
    field,

    const properties: std.enums.EnumFieldStruct(FieldLayoutColumn, DataType, null) = .{
        .offset = .{ .int = 4 },
        .field = .{ .index = .{ .table = .field } },
    };

    pub fn dataType(column: FieldLayoutColumn) DataType {
        return @field(properties, @tagName(column));
    }
};

pub const StandAloneSigColumn = enum {
    signature,

    const properties: std.enums.EnumFieldStruct(StandAloneSigColumn, DataType, null) = .{
        .signature = .{ .index = .{ .heap = .blob } },
    };

    pub fn dataType(column: StandAloneSigColumn) DataType {
        return @field(properties, @tagName(column));
    }
};

pub const EventMapColumn = enum {
    parent,
    event_list,

    const properties: std.enums.EnumFieldStruct(EventMapColumn, DataType, null) = .{
        .parent = .{ .index = .{ .table = .type_def } },
        .event_list = .{ .index = .{ .table = .event } },
    };

    pub fn dataType(column: EventMapColumn) DataType {
        return @field(properties, @tagName(column));
    }
};

pub const EventColumn = enum {
    event_flags,
    name,
    event_type,

    const properties: std.enums.EnumFieldStruct(EventColumn, DataType, null) = .{
        .event_flags = .{ .int = 2 },
        .name = .{ .index = .{ .heap = .string } },
        .event_type = .{ .index = .{ .coded = .type_def_or_ref } },
    };

    pub fn dataType(column: EventColumn) DataType {
        return @field(properties, @tagName(column));
    }
};

pub const PropertyMapColumn = enum {
    parent,
    property_list,

    const properties: std.enums.EnumFieldStruct(PropertyMapColumn, DataType, null) = .{
        .parent = .{ .index = .{ .table = .type_def } },
        .property_list = .{ .index = .{ .table = .property } },
    };

    pub fn dataType(column: PropertyMapColumn) DataType {
        return @field(properties, @tagName(column));
    }
};

pub const PropertyColumn = enum {
    flags,
    name,
    type,

    const properties: std.enums.EnumFieldStruct(PropertyColumn, DataType, null) = .{
        .flags = .{ .int = 2 },
        .name = .{ .index = .{ .heap = .string } },
        .type = .{ .index = .{ .heap = .blob } },
    };

    pub fn dataType(column: PropertyColumn) DataType {
        return @field(properties, @tagName(column));
    }
};

pub const MethodSemanticsColumn = enum {
    semantics,
    method,
    association,

    const properties: std.enums.EnumFieldStruct(MethodSemanticsColumn, DataType, null) = .{
        .semantics = .{ .int = 2 },
        .method = .{ .index = .{ .table = .method_def } },
        .association = .{ .index = .{ .coded = .has_semantics } },
    };

    pub fn dataType(column: MethodSemanticsColumn) DataType {
        return @field(properties, @tagName(column));
    }
};

pub const MethodImplColumn = enum {
    class,
    method_body,
    method_declaration,

    const properties: std.enums.EnumFieldStruct(MethodImplColumn, DataType, null) = .{
        .class = .{ .index = .{ .table = .type_def } },
        .method_body = .{ .index = .{ .coded = .method_def_or_ref } },
        .method_declaration = .{ .index = .{ .coded = .method_def_or_ref } },
    };

    pub fn dataType(column: MethodImplColumn) DataType {
        return @field(properties, @tagName(column));
    }
};

pub const ModuleRefColumn = enum {
    name,

    const properties: std.enums.EnumFieldStruct(ModuleRefColumn, DataType, null) = .{
        .name = .{ .index = .{ .heap = .string } },
    };

    pub fn dataType(column: ModuleRefColumn) DataType {
        return @field(properties, @tagName(column));
    }
};

pub const TypeSpecColumn = enum {
    signature,

    const properties: std.enums.EnumFieldStruct(TypeSpecColumn, DataType, null) = .{
        .signature = .{ .index = .{ .heap = .blob } },
    };

    pub fn dataType(column: TypeSpecColumn) DataType {
        return @field(properties, @tagName(column));
    }
};

pub const ImplMapColumn = enum {
    mapping_flags,
    member_forwarded,
    import_name,
    import_scope,

    const properties: std.enums.EnumFieldStruct(ImplMapColumn, DataType, null) = .{
        .mapping_flags = .{ .int = 2 },
        .member_forwarded = .{ .index = .{ .coded = .member_forwarded } },
        .import_name = .{ .index = .{ .heap = .string } },
        .import_scope = .{ .index = .{ .table = .module_ref } },
    };

    pub fn dataType(column: ImplMapColumn) DataType {
        return @field(properties, @tagName(column));
    }
};

pub const FieldRvaColumn = enum {
    rva,
    field,

    const properties: std.enums.EnumFieldStruct(FieldRvaColumn, DataType, null) = .{
        .rva = .{ .int = 4 },
        .field = .{ .index = .{ .table = .field } },
    };

    pub fn dataType(column: FieldRvaColumn) DataType {
        return @field(properties, @tagName(column));
    }
};

pub const AssemblyColumn = enum {
    hash_alg_id,
    versions,
    flags,
    public_key,
    name,
    culture,

    const properties: std.enums.EnumFieldStruct(AssemblyColumn, DataType, null) = .{
        .hash_alg_id = .{ .int = 4 },
        .versions = .{ .int = 8 },
        .flags = .{ .int = 4 },
        .public_key = .{ .index = .{ .heap = .blob } },
        .name = .{ .index = .{ .heap = .string } },
        .culture = .{ .index = .{ .heap = .string } },
    };

    pub fn dataType(column: AssemblyColumn) DataType {
        return @field(properties, @tagName(column));
    }
};

pub const AssemblyProcessorColumn = enum {
    processor,

    const properties: std.enums.EnumFieldStruct(AssemblyProcessorColumn, DataType, null) = .{
        .processor = .{ .int = 4 },
    };

    pub fn dataType(column: AssemblyProcessorColumn) DataType {
        return @field(properties, @tagName(column));
    }
};

pub const AssemblyOsColumn = enum {
    os_platform_id,
    os_major_version,
    os_minor_version,

    const properties: std.enums.EnumFieldStruct(AssemblyOsColumn, DataType, null) = .{
        .os_platform_id = .{ .int = 4 },
        .os_major_version = .{ .int = 4 },
        .os_minor_version = .{ .int = 4 },
    };

    pub fn dataType(column: AssemblyOsColumn) DataType {
        return @field(properties, @tagName(column));
    }
};

pub const AssemblyRefColumn = enum {
    versions,
    flags,
    public_key_or_token,
    name,
    culture,
    hash_value,

    const properties: std.enums.EnumFieldStruct(AssemblyRefColumn, DataType, null) = .{
        .versions = .{ .int = 8 },
        .flags = .{ .int = 4 },
        .public_key_or_token = .{ .index = .{ .heap = .blob } },
        .name = .{ .index = .{ .heap = .string } },
        .culture = .{ .index = .{ .heap = .string } },
        .hash_value = .{ .index = .{ .heap = .blob } },
    };

    pub fn dataType(column: AssemblyRefColumn) DataType {
        return @field(properties, @tagName(column));
    }
};

pub const AssemblyRefProcessorColumn = enum {
    processor,
    assembly_ref,

    const properties: std.enums.EnumFieldStruct(AssemblyRefProcessorColumn, DataType, null) = .{
        .processor = .{ .int = 4 },
        .assembly_ref = .{ .index = .{ .table = .assembly_ref } },
    };

    pub fn dataType(column: AssemblyRefProcessorColumn) DataType {
        return @field(properties, @tagName(column));
    }
};

pub const AssemblyRefOsColumn = enum {
    os_platform_id,
    os_major_version,
    os_minor_version,
    assembly_ref,

    const properties: std.enums.EnumFieldStruct(AssemblyRefOsColumn, DataType, null) = .{
        .os_platform_id = .{ .int = 4 },
        .os_major_version = .{ .int = 4 },
        .os_minor_version = .{ .int = 4 },
        .assembly_ref = .{ .index = .{ .table = .assembly_ref } },
    };

    pub fn dataType(column: AssemblyRefOsColumn) DataType {
        return @field(properties, @tagName(column));
    }
};

pub const FileColumn = enum {
    flags,
    name,
    hash_value,

    const properties: std.enums.EnumFieldStruct(FileColumn, DataType, null) = .{
        .flags = .{ .int = 4 },
        .name = .{ .index = .{ .heap = .string } },
        .hash_value = .{ .index = .{ .heap = .blob } },
    };

    pub fn dataType(column: FileColumn) DataType {
        return @field(properties, @tagName(column));
    }
};

pub const ExportedTypeColumn = enum {
    flags,
    type_def_id,
    type_name,
    type_namespace,
    implementation,

    const properties: std.enums.EnumFieldStruct(ExportedTypeColumn, DataType, null) = .{
        .flags = .{ .int = 4 },
        .type_def_id = .{ .int = 4 },
        .type_name = .{ .index = .{ .heap = .string } },
        .type_namespace = .{ .index = .{ .heap = .string } },
        .implementation = .{ .index = .{ .coded = .implementation } },
    };

    pub fn dataType(column: ExportedTypeColumn) DataType {
        return @field(properties, @tagName(column));
    }
};

pub const ManifestResourceColumn = enum {
    offset,
    flags,
    name,
    implementation,

    const properties: std.enums.EnumFieldStruct(ManifestResourceColumn, DataType, null) = .{
        .offset = .{ .int = 4 },
        .flags = .{ .int = 4 },
        .name = .{ .index = .{ .heap = .string } },
        .implementation = .{ .index = .{ .coded = .implementation } },
    };

    pub fn dataType(column: ManifestResourceColumn) DataType {
        return @field(properties, @tagName(column));
    }
};

pub const NestedClassColumn = enum {
    nested_class,
    enclosing_class,

    const properties: std.enums.EnumFieldStruct(NestedClassColumn, DataType, null) = .{
        .nested_class = .{ .index = .{ .table = .type_def } },
        .enclosing_class = .{ .index = .{ .table = .type_def } },
    };

    pub fn dataType(column: NestedClassColumn) DataType {
        return @field(properties, @tagName(column));
    }
};

pub const GenericParamColumn = enum {
    number,
    flags,
    owner,
    name,

    const properties: std.enums.EnumFieldStruct(GenericParamColumn, DataType, null) = .{
        .number = .{ .int = 2 },
        .flags = .{ .int = 2 },
        .owner = .{ .index = .{ .coded = .type_or_method_def } },
        .name = .{ .index = .{ .heap = .string } },
    };

    pub fn dataType(column: GenericParamColumn) DataType {
        return @field(properties, @tagName(column));
    }
};

pub const MethodSpecColumn = enum {
    method,
    instantiation,

    const properties: std.enums.EnumFieldStruct(MethodSpecColumn, DataType, null) = .{
        .method = .{ .index = .{ .coded = .method_def_or_ref } },
        .instantiation = .{ .index = .{ .heap = .blob } },
    };

    pub fn dataType(column: MethodSpecColumn) DataType {
        return @field(properties, @tagName(column));
    }
};

pub const GenericParamConstraintColumn = enum {
    owner,
    constraint,

    const properties: std.enums.EnumFieldStruct(GenericParamConstraintColumn, DataType, null) = .{
        .owner = .{ .index = .{ .table = .generic_param } },
        .constraint = .{ .index = .{ .coded = .type_def_or_ref } },
    };

    pub fn dataType(column: GenericParamConstraintColumn) DataType {
        return @field(properties, @tagName(column));
    }
};

pub const CodedIndex = enum {
    type_def_or_ref,
    has_constant,
    has_custom_attribute,
    has_field_marshal,
    has_decl_security,
    member_ref_parent,
    has_semantics,
    method_def_or_ref,
    member_forwarded,
    implementation,
    custom_attribute_type,
    resolution_scope,
    type_or_method_def,

    const properties: std.enums.EnumFieldStruct(CodedIndex, struct {
        u16,
        std.enums.EnumFieldStruct(Table, ?u5, @as(?u5, null)),
    }, null) = .{
        .type_def_or_ref = .{ 2, .{
            .type_def = 0,
            .type_ref = 1,
            .type_spec = 2,
        } },
        .has_constant = .{ 2, .{
            .field = 0,
            .param = 1,
            .property = 2,
        } },
        .has_custom_attribute = .{ 5, .{
            .method_def = 0,
            .field = 1,
            .type_ref = 2,
            .type_def = 3,
            .param = 4,
            .interface_impl = 5,
            .member_ref = 6,
            .module = 7,
            .property = 9,
            .event = 10,
            .stand_alone_sig = 11,
            .module_ref = 12,
            .type_spec = 13,
            .assembly = 14,
            .assembly_ref = 15,
            .file = 16,
            .exported_type = 17,
            .manifest_resource = 18,
            .generic_param = 19,
            .generic_param_constraint = 20,
            .method_spec = 21,
        } },
        .has_field_marshal = .{ 1, .{
            .field = 0,
            .param = 1,
        } },
        .has_decl_security = .{ 2, .{
            .type_def = 0,
            .method_def = 1,
            .assembly = 2,
        } },
        .member_ref_parent = .{ 3, .{
            .type_def = 0,
            .type_ref = 1,
            .module_ref = 2,
            .method_def = 3,
            .type_spec = 4,
        } },
        .has_semantics = .{ 1, .{
            .event = 0,
            .property = 1,
        } },
        .method_def_or_ref = .{ 1, .{
            .method_def = 0,
            .member_ref = 1,
        } },
        .member_forwarded = .{ 1, .{
            .field = 0,
            .method_def = 1,
        } },
        .implementation = .{ 2, .{
            .file = 0,
            .assembly_ref = 1,
            .exported_type = 2,
        } },
        .custom_attribute_type = .{ 3, .{
            .method_def = 2,
            .member_ref = 3,
        } },
        .resolution_scope = .{ 2, .{
            .module = 0,
            .module_ref = 1,
            .assembly_ref = 2,
            .type_ref = 3,
        } },
        .type_or_method_def = .{ 1, .{
            .type_def = 0,
            .method_def = 1,
        } },
    };

    pub fn tagBits(index: CodedIndex) u16 {
        return @field(properties, @tagName(index))[0];
    }

    pub fn tags(index: CodedIndex) std.enums.EnumFieldStruct(Table, ?u5, @as(?u5, null)) {
        return @field(properties, @tagName(index))[1];
    }

    pub fn Tag(index: CodedIndex) type {
        const tag_enum_bits = index.tagBits();

        const tag_type = @Type(.{ .int = .{
            .signedness = .unsigned,
            .bits = tag_enum_bits,
        } });

        const tags_struct = index.tags();
        const tags_struct_fields = @typeInfo(@TypeOf(tags_struct)).@"struct".fields;
        var tag_enum_fields: []const std.builtin.Type.EnumField = &.{};

        for (tags_struct_fields) |tags_struct_field| {
            if (@field(tags_struct, tags_struct_field.name)) |tag_value| {
                tag_enum_fields = tag_enum_fields ++ .{std.builtin.Type.EnumField{
                    .name = tags_struct_field.name,
                    .value = tag_value,
                }};
            }
        }

        return @Type(.{ .@"enum" = .{
            .tag_type = tag_type,
            .fields = tag_enum_fields,
            .decls = &.{},
            .is_exhaustive = true,
        } });
    }
};

pub const Index = union(enum) {
    heap: Heap,
    table: Table,
    coded: CodedIndex,
};

const DataType = union(enum) {
    int: u16,
    index: Index,

    pub fn Type(data_type: DataType) type {
        return switch (data_type) {
            .int => |bytes| @Type(.{ .int = .{
                .signedness = .unsigned,
                .bits = 8 * bytes,
            } }),
            .index => |index| switch (index) {
                .heap, .table => u32,
                .coded => |coded| struct {
                    tag: coded.Tag(),
                    value: u32,
                },
            },
        };
    }
};

pub const TableStream = struct {
    reserved0: u32,
    major_version: u8,
    minor_version: u8,
    heap_sizes: u8,
    reserved1: u8,
    valid: u64,
    sorted: u64,
    rows: std.ArrayList(u32),
    tables: Tables,

    pub fn read(allocator: std.mem.Allocator, bytes: []const u8) !TableStream {
        var stream = std.io.fixedBufferStream(bytes);
        const reader = stream.reader();

        const raw_table_stream_0 = try reader.readStructEndian(extern struct {
            Reserved0: u32,
            MajorVersion: u8,
            MinorVersion: u8,
            HeapSizes: u8,
            Reserved1: u8,
            Valid: u64,
            Sorted: u64,
        }, .little);

        const table_tags = comptime std.enums.values(Table);
        var valid_vector = raw_table_stream_0.Valid;
        var rows = try std.ArrayList(u32).initCapacity(allocator, @popCount(raw_table_stream_0.Valid));
        errdefer rows.deinit();
        var initialized_tables = std.enums.EnumSet(Table).initEmpty();
        var tables: Tables = undefined;

        errdefer {
            @setEvalBranchQuota(4000);

            inline for (table_tags) |table_tag| {
                if (initialized_tables.contains(table_tag)) {
                    @field(tables, @tagName(table_tag)).deinit();
                }
            }
        }

        inline for (table_tags) |table_tag| {
            const valid_bit = table_tag.validBit();

            if (valid_vector & valid_bit == 0) {
                @field(tables, @tagName(table_tag)) = @FieldType(Tables, @tagName(table_tag)).init(allocator);
            } else {
                valid_vector &= ~valid_bit;
                const table_len = try reader.readInt(u32, .little);
                rows.appendAssumeCapacity(table_len);
                @field(tables, @tagName(table_tag)) = try @FieldType(Tables, @tagName(table_tag)).initCapacity(allocator, table_len);
            }
        }

        if (valid_vector != 0) return error.PeInvalidTableValidVector;

        return .{
            .reserved0 = raw_table_stream_0.Reserved0,
            .major_version = raw_table_stream_0.MajorVersion,
            .minor_version = raw_table_stream_0.MinorVersion,
            .heap_sizes = raw_table_stream_0.HeapSizes,
            .reserved1 = raw_table_stream_0.Reserved1,
            .valid = raw_table_stream_0.Valid,
            .sorted = raw_table_stream_0.Sorted,
            .rows = rows,
            .tables = tables,
        };
    }

    pub fn free(stream: TableStream) void {
        stream.rows.deinit();
        const tables_struct_fields = @typeInfo(Tables).@"struct".fields;

        inline for (tables_struct_fields) |tables_struct_field| {
            @field(stream.tables, tables_struct_field.name).deinit();
        }
    }
};

pub const Tables = blk: {
    const table_tags = std.enums.values(Table);
    var tables_struct_fields: [table_tags.len]std.builtin.Type.StructField = undefined;

    for (&tables_struct_fields, table_tags) |*tables_struct_field, table_tag| {
        const TablesFieldType = std.ArrayList(table_tag.Row());

        tables_struct_field.* = .{
            .name = @tagName(table_tag),
            .type = TablesFieldType,
            .default_value_ptr = null,
            .is_comptime = false,
            .alignment = @alignOf(TablesFieldType),
        };
    }

    break :blk @Type(.{ .@"struct" = .{
        .layout = .auto,
        .fields = &tables_struct_fields,
        .decls = &.{},
        .is_tuple = false,
    } });
};
