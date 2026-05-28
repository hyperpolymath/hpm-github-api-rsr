// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
//
// Zig build script for hpm-github-api-rsr.
//
// Links the three sibling RSR libraries. By default we look for them in
// ../../hpm-{crypto,http-client,json}-rsr/ffi/zig/zig-out — change with
// the -Dsibling-prefix option if your layout differs.

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const sibling_prefix = b.option(
        []const u8,
        "sibling-prefix",
        "Path containing hpm-{crypto,http-client,json}-rsr sibling repos",
    ) orelse "../../..";

    const crypto_lib_path = b.fmt("{s}/hpm-crypto-rsr/ffi/zig/zig-out/lib", .{sibling_prefix});
    const http_lib_path = b.fmt("{s}/hpm-http-client-rsr/ffi/zig/zig-out/lib", .{sibling_prefix});
    const json_lib_path = b.fmt("{s}/hpm-json-rsr/ffi/zig/zig-out/lib", .{sibling_prefix});

    const root_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    root_mod.addLibraryPath(.{ .cwd_relative = crypto_lib_path });
    root_mod.addLibraryPath(.{ .cwd_relative = http_lib_path });
    root_mod.addLibraryPath(.{ .cwd_relative = json_lib_path });
    root_mod.linkSystemLibrary("hpm_crypto", .{});
    root_mod.linkSystemLibrary("hpm_http_client", .{});
    root_mod.linkSystemLibrary("hpm_json", .{});

    const shared = b.addLibrary(.{
        .name = "hpm_github_api",
        .root_module = root_mod,
        .linkage = .dynamic,
    });
    b.installArtifact(shared);

    const static = b.addLibrary(.{
        .name = "hpm_github_api",
        .root_module = root_mod,
        .linkage = .static,
    });
    b.installArtifact(static);

    const tests = b.addTest(.{
        .root_module = root_mod,
    });
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);
}
