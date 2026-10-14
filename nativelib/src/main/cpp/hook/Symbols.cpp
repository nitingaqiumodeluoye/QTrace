//
// 符号表实现。见 include/Symbols.h 顶部关于「为什么不用 dladdr」的说明。
//
#include "Symbols.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <elf.h>
#include <fcntl.h>
#include <unistd.h>

#include "logger.h"

namespace {

struct SymEntry {
    uint64_t addr;
    uint32_t name_off;   // 在 Module::names 池中的偏移
};

struct Module {
    uint64_t base = 0;          // ELF 装载基址（file offset == 0 的那个映射）
    std::string path;
    bool parsed = false;
    std::vector<char> names;    // 名字池
    std::vector<SymEntry> syms; // 按 addr 升序
};

// 一段可执行的、有文件支撑的映射
struct Mapping {
    uint64_t start = 0;
    uint64_t end = 0;
    uint64_t file_off = 0;
    uint32_t module_idx = 0;
};

std::vector<Module> g_modules;
std::vector<Mapping> g_mappings;
bool g_inited = false;

constexpr size_t MAX_PARSE_BYTES = 64u * 1024 * 1024; // 单模块符号表上限，防御性

bool read_at(int fd, void *buf, size_t len, off_t off)
{
    size_t got = 0;
    while (got < len) {
        ssize_t n = pread(fd, static_cast<char *>(buf) + got, len - got, off + (off_t)got);
        if (n <= 0) {
            return false;
        }
        got += static_cast<size_t>(n);
    }
    return true;
}

// 把一张符号表（.dynsym 或 .symtab）里的函数符号并入模块
void ingest_symtab(Module &m, int fd, const Elf64_Shdr &symtab,
                   const Elf64_Shdr &strtab)
{
    if (symtab.sh_size == 0 || symtab.sh_entsize == 0 || strtab.sh_size == 0) {
        return;
    }
    if (symtab.sh_size > MAX_PARSE_BYTES || strtab.sh_size > MAX_PARSE_BYTES) {
        return;
    }

    std::vector<Elf64_Sym> syms(symtab.sh_size / sizeof(Elf64_Sym));
    if (!read_at(fd, syms.data(), symtab.sh_size, (off_t)symtab.sh_offset)) {
        return;
    }
    std::vector<char> strs(strtab.sh_size);
    if (!read_at(fd, strs.data(), strtab.sh_size, (off_t)strtab.sh_offset)) {
        return;
    }

    for (const Elf64_Sym &s : syms) {
        if (s.st_value == 0 || s.st_name == 0 || s.st_name >= strs.size()) {
            continue;
        }
        unsigned type = ELF64_ST_TYPE(s.st_info);
        // 只要函数（含 GNU ifunc）
        if (type != STT_FUNC && type != STT_GNU_IFUNC) {
            continue;
        }
        const char *nm = strs.data() + s.st_name;
        size_t max_len = strs.size() - s.st_name;
        size_t nm_len = strnlen(nm, max_len);
        if (nm_len == 0 || nm_len >= max_len) {
            continue;
        }

        uint32_t off = static_cast<uint32_t>(m.names.size());
        m.names.insert(m.names.end(), nm, nm + nm_len + 1); // 含终止符
        m.syms.push_back(SymEntry{ m.base + s.st_value, off });
    }
}

// 惰性解析模块的符号表
void parse_module(Module &m)
{
    m.parsed = true; // 失败也只尝试一次
    if (m.path.empty() || m.path[0] != '/') {
        return;
    }

    int fd = open(m.path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return;
    }

    Elf64_Ehdr eh;
    if (!read_at(fd, &eh, sizeof(eh), 0) ||
        memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 ||
        eh.e_ident[EI_CLASS] != ELFCLASS64 ||
        eh.e_shoff == 0 || eh.e_shnum == 0 || eh.e_shentsize != sizeof(Elf64_Shdr)) {
        close(fd);
        return;
    }
    if ((uint64_t)eh.e_shnum * sizeof(Elf64_Shdr) > MAX_PARSE_BYTES) {
        close(fd);
        return;
    }

    std::vector<Elf64_Shdr> shdrs(eh.e_shnum);
    if (!read_at(fd, shdrs.data(), (size_t)eh.e_shnum * sizeof(Elf64_Shdr),
                 (off_t)eh.e_shoff)) {
        close(fd);
        return;
    }

    // 先 .dynsym（导出符号，发布版必有），再 .symtab（未 strip 时更全）
    for (int pass = 0; pass < 2; ++pass) {
        const uint32_t want = (pass == 0) ? SHT_DYNSYM : SHT_SYMTAB;
        for (const Elf64_Shdr &sh : shdrs) {
            if (sh.sh_type != want || sh.sh_link >= shdrs.size()) {
                continue;
            }
            const Elf64_Shdr &strtab = shdrs[sh.sh_link];
            if (strtab.sh_type != SHT_STRTAB) {
                continue;
            }
            ingest_symtab(m, fd, sh, strtab);
        }
    }

    close(fd);

    if (m.syms.empty()) {
        return;
    }
    std::sort(m.syms.begin(), m.syms.end(),
              [](const SymEntry &a, const SymEntry &b) { return a.addr < b.addr; });
    m.syms.erase(std::unique(m.syms.begin(), m.syms.end(),
                             [](const SymEntry &a, const SymEntry &b) {
                                 return a.addr == b.addr;
                             }),
                 m.syms.end());
    LOGI("symbols: %s -> %zu syms", m.path.c_str(), m.syms.size());
}

const Module *module_for_addr(uint64_t addr, bool *need_parse, uint32_t *idx)
{
    for (const Mapping &mp : g_mappings) {
        if (addr >= mp.start && addr < mp.end) {
            const Module &m = g_modules[mp.module_idx];
            if (!m.parsed) {
                *need_parse = true;
                *idx = mp.module_idx;
            }
            return &m;
        }
    }
    return nullptr;
}

} // namespace

void symbols_init()
{
    if (g_inited) {
        return;
    }
    g_inited = true;

    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp == nullptr) {
        LOGE("symbols: cannot open /proc/self/maps");
        return;
    }

    struct RawLine {
        uint64_t start, end, file_off;
        bool exec;
        std::string path;
    };
    std::vector<RawLine> raws;

    char *line = nullptr;
    size_t cap = 0;
    while (getline(&line, &cap, fp) != -1) {
        uint64_t start = 0, end = 0, file_off = 0;
        char perms[8] = {0};
        char path[4096] = {0};
        int n = sscanf(line, "%lx-%lx %7s %lx %*s %*s %4095[^\n]",
                       &start, &end, perms, &file_off, path);
        if (n < 4) {
            continue;
        }
        // 去尾部空白（匿名映射行常带空格）
        for (char *p = path + strlen(path); p > path && isspace((unsigned char)p[-1]); --p) {
            p[-1] = '\0';
        }
        if (path[0] != '/') {   // 只要文件支撑的映射
            continue;
        }
        // 注意：必须收集**全部**权限的映射才能算对模块基址 ——
        // ELF 装载基址是 file offset 为 0 的那个映射（通常是 r-- 段），
        // 而可执行段（r-x）的 file offset 一般不为 0。
        raws.push_back(RawLine{ start, end, file_off, perms[2] == 'x', std::string(path) });
    }
    free(line);
    fclose(fp);

    // 按路径归组：base = file offset 为 0 的那个映射起点
    for (const RawLine &r : raws) {
        uint32_t idx = UINT32_MAX;
        for (uint32_t i = 0; i < g_modules.size(); ++i) {
            if (g_modules[i].path == r.path) {
                idx = i;
                break;
            }
        }
        if (idx == UINT32_MAX) {
            Module m;
            m.path = r.path;
            m.base = UINT64_MAX;   // 稍后用 offset==0 的映射修正
            g_modules.push_back(std::move(m));
            idx = (uint32_t)(g_modules.size() - 1);
        }
        if (r.file_off == 0 && r.start < g_modules[idx].base) {
            g_modules[idx].base = r.start;
        }
        if (!r.exec) {
            continue;   // 非可执行段不作为查找范围
        }
        Mapping mp;
        mp.start = r.start;
        mp.end = r.end;
        mp.file_off = r.file_off;
        mp.module_idx = idx;
        g_mappings.push_back(mp);
    }

    // 兜底：某些模块（很少有）没有 file offset 为 0 的映射，此时用最小起点
    for (Module &m : g_modules) {
        if (m.base != UINT64_MAX) {
            continue;
        }
        uint64_t best = UINT64_MAX;
        for (const Mapping &mp : g_mappings) {
            if (mp.module_idx >= g_modules.size()) {
                continue;
            }
            if (&g_modules[mp.module_idx] == &m && mp.start < best) {
                best = mp.start;
            }
        }
        m.base = (best == UINT64_MAX) ? 0 : best;
    }    std::sort(g_mappings.begin(), g_mappings.end(),
              [](const Mapping &a, const Mapping &b) { return a.start < b.start; });

    LOGI("symbols: %zu modules, %zu exec mappings (lazy symtab parse)",
         g_modules.size(), g_mappings.size());
}

const char *symbols_lookup_exact(uint64_t addr)
{
    if (!g_inited || addr == 0) {
        return nullptr;
    }
    bool need_parse = false;
    uint32_t idx = 0;
    const Module *m = module_for_addr(addr, &need_parse, &idx);
    if (m == nullptr) {
        return nullptr;
    }
    if (need_parse) {
        parse_module(g_modules[idx]);
        m = &g_modules[idx];
    }
    if (m->syms.empty()) {
        return nullptr;
    }

    auto it = std::lower_bound(m->syms.begin(), m->syms.end(), addr,
                               [](const SymEntry &e, uint64_t v) { return e.addr < v; });
    if (it == m->syms.end() || it->addr != addr) {
        return nullptr;
    }
    return m->names.data() + it->name_off;
}

const char *symbols_lookup_containing(uint64_t addr, uint64_t *sym_start)
{
    if (sym_start != nullptr) {
        *sym_start = 0;
    }
    if (!g_inited || addr == 0) {
        return nullptr;
    }
    bool need_parse = false;
    uint32_t idx = 0;
    const Module *m = module_for_addr(addr, &need_parse, &idx);
    if (m == nullptr) {
        return nullptr;
    }
    if (need_parse) {
        parse_module(g_modules[idx]);
        m = &g_modules[idx];
    }
    if (m->syms.empty()) {
        return nullptr;
    }

    auto it = std::upper_bound(m->syms.begin(), m->syms.end(), addr,
                               [](uint64_t v, const SymEntry &e) { return v < e.addr; });
    if (it == m->syms.begin()) {
        return nullptr;
    }
    --it;
    if (sym_start != nullptr) {
        *sym_start = it->addr;
    }
    return m->names.data() + it->name_off;
}
