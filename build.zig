const std = @import("std");

pub fn build(b: *std.Build) void {
    const name = "peformat";
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const module = b.addModule(name, .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const zigwin32 = b.dependency("zigwin32", .{});
    const win32_module = zigwin32.module("win32");
    module.addImport("win32", win32_module);

    const check_compile = b.addLibrary(.{
        .name = name,
        .root_module = module,
    });

    const check_step = b.step("check", "Check the library");
    check_step.dependOn(&check_compile.step);

    const test_compile = b.addTest(.{
        .root_module = module,
    });

    const test_run = b.addRunArtifact(test_compile);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&test_run.step);
}
