const std = @import("std");
const clap = @import("clap");

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    const stderr = std.io.getStdErr().writer();

    const params = comptime [_]clap.Param(clap.Help){
        clap.parseParam("-h, --help       Display this help and exit.") catch unreachable,
        clap.parseParam("--header         Display Header             ") catch unreachable,
        clap.parseParam("--sections       Display Sections           ") catch unreachable,
        clap.parseParam("--symbols        Display Symbols            ") catch unreachable,
        clap.parseParam("--relocations    Display Relocations        ") catch unreachable,
        clap.parseParam("--programheaders Display Program Headers    ") catch unreachable,
        clap.parseParam("-a, --all        Display All                ") catch unreachable,
        clap.parseParam("<file>           The input file.            ") catch unreachable,
    };

    var args = try clap.parse(clap.Help, &params, .{});
    defer args.deinit();

    if (args.flag("--help")) {
        try clap.help(stderr, &params);
        return;
    }

    if (args.positionals().len != 1) return error.ExpectedFileArgument;
    const file = try std.fs.cwd().openFile(args.positionals()[0], .{});
    defer file.close();

    const all = args.flag("--all");
    const is_64 = (try std.elf.Header.read(file)).is_64;
    if (is_64) {
        const map = try Mapping(true).initFromFile(file);
        defer map.deinit();
        if (args.flag("--header") or all) try dumpHeader(stdout, map);
        if (args.flag("--sections") or all) try dumpSections(stdout, map);
        if (args.flag("--symbols") or all) try dumpSymbols(stdout, map);
        if (args.flag("--relocations") or all) try dumpRelocations(stdout, map);
        if (args.flag("--programheaders") or all) try dumpProgramHeaders(stdout, map);
    } else {
        const map = try Mapping(false).initFromFile(file);
        defer map.deinit();
        if (args.flag("--header") or all) try dumpHeader(stdout, map);
        if (args.flag("--sections") or all) try dumpSections(stdout, map);
        if (args.flag("--symbols") or all) try dumpSymbols(stdout, map);
        if (args.flag("--relocations") or all) try dumpRelocations(stdout, map);
        if (args.flag("--programheaders") or all) try dumpProgramHeaders(stdout, map);
    }
}

fn Mapping(comptime is_64: bool) type {
    return struct {
        const Map = @This();

        const Shdr = if (is_64) std.elf.Elf64_Shdr else std.elf.Elf32_Shdr;
        const Ehdr = if (is_64) std.elf.Elf64_Ehdr else std.elf.Elf32_Ehdr;
        const Phdr = if (is_64) std.elf.Elf64_Phdr else std.elf.Elf32_Phdr;
        const Sym = if (is_64) std.elf.Elf64_Sym else std.elf.Elf32_Sym;
        const Dyn = if (is_64) std.elf.Elf64_Dyn else std.elf.Elf32_Dyn;
        const Rela = if (is_64) Rela_64 else Rela_32;

        raw: []align(std.mem.page_size) const u8,
        fn initFromFile(file: std.fs.File) !Map {
            return Map{
                .raw = try std.os.mmap(
                    null,
                    @intCast(usize, (try file.stat()).size),
                    std.os.PROT.READ,
                    std.os.MAP.PRIVATE,
                    file.handle,
                    0,
                ),
            };
        }
        fn deinit(self: Map) void {
            std.os.munmap(self.raw);
        }
        fn header(self: Map) std.elf.Header {
            //reading 0..@sizeOf(Elf64_Ehdr) is reading more than necessary on 32 bit elf files
            //but works around a compile error... and should be totally harmless
            return std.elf.Header.parse(self.raw.ptr[0..@sizeOf(std.elf.Elf64_Ehdr)]) catch unreachable;
        }
        fn sectionHeaders(self: Map) []const Shdr {
            const h = self.header();
            return @ptrCast(
                [*]const Shdr,
                @alignCast(@alignOf(Shdr), self.raw.ptr + h.shoff),
            )[0..h.shnum];
        }
        fn sectionNameZ(self: Map, section_header: Shdr) [*:0]const u8 {
            const h = self.header();
            return @ptrCast(
                [*:0]const u8,
                self.raw.ptr + self.sectionHeaders()[h.shstrndx].sh_offset + section_header.sh_name,
            );
        }
        fn sectionName(self: Map, section_header: Shdr) []const u8 {
            return std.mem.span(self.sectionNameZ(section_header));
        }
        fn symbols(self: Map) []const Sym {
            return @ptrCast(
                [*]const Sym,
                @alignCast(@alignOf(Sym), self.raw.ptr + self.symtab().sh_offset),
            )[0 .. self.symtab().sh_size / @sizeOf(Sym)];
        }
        fn symbolNameZ(self: Map, symbol: Sym) [*:0]const u8 {
            return @ptrCast(
                [*:0]const u8,
                self.raw.ptr + self.strtab().sh_offset + symbol.st_name,
            );
        }
        fn symbolName(self: Map, symbol: Sym) []const u8 {
            return std.mem.span(self.symbolNameZ(symbol));
        }
        fn symtab(self: Map) Shdr {
            return for (self.sectionHeaders()) |section_header| {
                const name = self.sectionName(section_header);
                if (std.mem.eql(u8, ".symtab", name)) break section_header;
            } else @panic("No .symtab section");
        }
        fn strtab(self: Map) Shdr {
            return for (self.sectionHeaders()) |section_header| {
                const name = self.sectionName(section_header);
                if (std.mem.eql(u8, ".strtab", name)) break section_header;
            } else @panic("No .strtab section");
        }
        fn dynsym(self: Map) Shdr {
            return for (self.sectionHeaders()) |section_header| {
                const name = self.sectionName(section_header);
                if (std.mem.eql(u8, ".dynsym", name)) break section_header;
            } else @panic("No .dynsym section");
        }
        fn dynstr(self: Map) Shdr {
            return for (self.sectionHeaders()) |section_header| {
                const name = self.sectionName(section_header);
                if (std.mem.eql(u8, ".dynstr", name)) break section_header;
            } else @panic("No .dynstr section");
        }
        fn relocationsRela(self: Map, section_header: Shdr) []const Rela {
            std.debug.assert(section_header.sh_type == std.elf.SHT_RELA);
            return @ptrCast(
                [*]const Rela,
                @alignCast(@alignOf(Rela), self.raw.ptr + section_header.sh_offset),
            )[0 .. section_header.sh_size / section_header.sh_entsize];
        }
        fn programHeaders(self: Map) []const Phdr {
            const h = self.header();
            return @ptrCast(
                [*]const Phdr,
                @alignCast(@alignOf(Phdr), self.raw.ptr + h.phoff),
            )[0..h.phnum];
        }
    };
}

fn dumpHeader(writer: anytype, map: anytype) !void {
    try writer.print("{}\n", .{map.header()});
}

fn dumpSections(writer: anytype, map: anytype) !void {
    for (map.sectionHeaders()) |section_header| {
        try writer.print("\"{s}\"\n    {}\n", .{ map.sectionName(section_header), section_header });
    }
}

fn dumpSymbols(writer: anytype, map: anytype) !void {
    for (map.symbols()) |symbol| {
        try writer.print("\"{s}\"\n    {}\n", .{ map.symbolName(symbol), symbol });
    }
}

fn dumpRelocations(writer: anytype, map: anytype) !void {
    for (map.sectionHeaders()) |section_header| switch (section_header.sh_type) {
        std.elf.SHT_RELA => for (map.relocationsRela(section_header)) |rela| {
            const symbolType: enum { symtab, dynsym } = blk: {
                const section_name = map.sectionName(map.sectionHeaders()[section_header.sh_link]);
                if (std.mem.eql(u8, ".symtab", section_name))
                    break :blk .symtab
                else if (std.mem.eql(u8, ".dynsym", section_name))
                    break :blk .dynsym
                else
                    unreachable; //TODO: properly handle
            };

            if (symbolType == .dynsym) @panic("SHT_RELA .dynsym unimplemented");

            const symbol_name = map.symbolName(map.symbols()[rela.r_info.sym]);
            const symbol_section_name = map.sectionName(map.sectionHeaders()[map.symbols()[rela.r_info.sym].st_shndx]);
            //NOTE: this is what readelf -r seems to do...
            const name = if (symbol_name.len > 0) symbol_name else symbol_section_name;

            try writer.print(
                "        {x:0>12} {x:0>12} {s: <16} {s} + {x}\n",
                .{
                    rela.r_offset,
                    @bitCast(u64, rela.r_info),
                    @tagName(rela.r_info.type_id),
                    name,
                    rela.r_addend,
                },
            );
        },
        std.elf.SHT_REL => @panic("SHT_REL unimplemented"),
        else => {},
    };
}

fn dumpProgramHeaders(writer: anytype, map: anytype) !void {
    for (map.programHeaders()) |program_header| {
        try writer.print("{}\n", .{program_header});
    }
}

const Reloc = enum(u8) {
    AMD64_NONE,
    AMD64_64,
    AMD64_PC32,
    AMD64_GOT32,
    AMD64_PLT32,
    AMD64_COPY,
    AMD64_GLOB_DAT,
    AMD64_JUMP_SLOT,
    AMD64_RELATIVE,
    AMD64_GOTPCREL,
    AMD64_32,
    AMD64_32s,
    AMD64_16,
    AMD64_PC16,
    AMD64_8,
    AMD64_PC8,
    AMD64_PC64,
    AMD64_GOTOFF64,
    AMD64_GOTPC32,
    AMD64_SIZE32,
    AMD64_SIZE64,
    _,
};

const R_INFO = packed struct {
    type_id: Reloc,
    byte1: u8, //part of type_info, workaround for packed struct bugs
    byte2: u8, //part of type_info, workaround for packed struct bugs
    byte3: u8, //part of type_info, workaround for packed struct bugs
    sym: u32,
    fn type_info(self: @This()) u24 {
        return @bitCast(u24, [_]u8{ self.byte1, self.byte2, self.byte3 });
    }
};

const Rela_64 = packed struct {
    r_offset: u64,
    r_info: R_INFO,
    r_addend: i64,
};

const Rela_32 = packed struct {
    r_offset: u32,
    r_info: R_INFO,
    r_addend: i32,
};
