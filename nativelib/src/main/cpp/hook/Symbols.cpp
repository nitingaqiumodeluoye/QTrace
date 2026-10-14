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
    uint32_t seq;        // 枚举顺序（见 parse_module 里同地址去重的说明）
};

struct Module {
    uint64_t base = 0;          // ELF 装载基址（file offset == 0 的那个映射）
    std::string path;
    bool parsed = false;
    uint32_t seq = 0;           // 符号枚举计数器
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

// ELF 的 PT_LOAD 段（只留判权限要用的字段）
struct LoadSeg {
    uint64_t vaddr = 0;
    uint64_t memsz = 0;
    uint32_t flags = 0;
};

/* 符号是否落在可读的 PT_LOAD 段里。
 * 对应 Frida 的 gum_parse_phdr_protection：段含 PF_R 即 GUM_PAGE_READ，
 * 而 GumTrace 的回调正是用它做 (section->protection & GUM_PAGE_READ) 判定。 */
bool addr_in_readable_load(const std::vector<LoadSeg> &loads, uint64_t vaddr)
{
    for (const LoadSeg &s : loads) {
        if (s.vaddr <= vaddr && vaddr < s.vaddr + s.memsz) {
            return (s.flags & PF_R) != 0;
        }
    }
    return false;
}

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

/* 把一张符号表（.symtab 或 .dynsym）里的符号并入模块。
 * 返回**枚举到的符号条目数**（含后来被过滤掉的）：调用方用它复现 Frida 的
 * “.symtab 一个都没发出才回退 .dynsym”行为。
 *
 * 过滤规则对齐 GumTrace（即 Frida 的 gum_module_enumerate_symbols 链路）：
 *   - **不按 STT 类型过滤**：只要符号所在 section 参与运行时可读映射，
 *     数据符号（STT_OBJECT/STT_NOTYPE）也收。
 *     Frida 的 gum_emit_symbol（backend-elf/gummodule-elf.c）把
 *     GUM_ELF_SYMBOL_* 全数回调，不做类型筛；GumTrace 的回调只检查
 *     address != 0 与 (section->protection & GUM_PAGE_READ)。
 *   - “可读”的判据是 section 的**地址所在 PT_LOAD 段**含 PF_R
 *     （gum_elf_module_load_section_details 用
      *      gum_elf_module_find_address_protection 按 program header 算 protection）。
 *     ELF 里非分配段（SHF_ALLOC 未置位）在运行时不存在，直接排除；
 *     SHN_UNDEF / SHN_ABS / SHN_COMMON 这类没有 section 的符号
 *     在 Frida 里 section == NULL，同样排除。
 *
 * 旧实现只要 STT_FUNC / STT_GNU_IFUNC，因此 local 符号与数据符号全都漏了，
 * 比 GumTrace 窄。 */
size_t ingest_symtab(Module &m, int fd, const Elf64_Shdr &symtab,
                     const Elf64_Shdr &strtab, const std::vector<Elf64_Shdr> &shdrs,
                     const std::vector<LoadSeg> &loads)
{
    if (symtab.sh_size == 0 || symtab.sh_entsize == 0 || strtab.sh_size == 0) {
        return 0;
    }
    if (symtab.sh_size > MAX_PARSE_BYTES || strtab.sh_size > MAX_PARSE_BYTES) {
        return 0;
    }

    std::vector<Elf64_Sym> syms(symtab.sh_size / sizeof(Elf64_Sym));
    if (!read_at(fd, syms.data(), symtab.sh_size, (off_t)symtab.sh_offset)) {
        return 0;
    }
    std::vector<char> strs(strtab.sh_size);
    if (!read_at(fd, strs.data(), strtab.sh_size, (off_t)strtab.sh_offset)) {
        return 0;
    }

    size_t seen = 0;
    for (const Elf64_Sym &s : syms) {
        if (s.st_name == 0 || s.st_name >= strs.size()) {
            continue;
        }
        ++seen;
        if (s.st_value == 0) {
            continue;
        }
        // 没有 section 的符号（未定义/绝对/COMMON）在 Frida 里是 section == NULL，排除
        if (s.st_shndx == SHN_UNDEF || s.st_shndx >= SHN_LORESERVE ||
            s.st_shndx >= shdrs.size()) {
            continue;
        }
        // 不参与运行时的 section（未置 SHF_ALLOC）没有映射，保护位算不出来，排除
        if ((shdrs[s.st_shndx].sh_flags & SHF_ALLOC) == 0) {
            continue;
        }
        // 真正对应 GumTrace 的 (section->protection & GUM_PAGE_READ)
        if (!addr_in_readable_load(loads, s.st_value)) {
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
        m.syms.push_back(SymEntry{ m.base + s.st_value, off, m.seq++ });
    }

    return seen;
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

    /* 读 PT_LOAD 段：GumTrace 的过滤条件是“符号所在 section 可读”，
     * 而 Frida 的 protection 是按 program header 的 PF_R 算的
     * （gum_elf_module_find_address_protection -> gum_parse_phdr_protection）。 */
    std::vector<LoadSeg> loads;
    if (eh.e_phoff != 0 && eh.e_phnum != 0 &&
        eh.e_phentsize == sizeof(Elf64_Phdr) &&
        (uint64_t)eh.e_phnum * sizeof(Elf64_Phdr) <= MAX_PARSE_BYTES) {
        std::vector<Elf64_Phdr> phdrs(eh.e_phnum);
        if (read_at(fd, phdrs.data(), (size_t)eh.e_phnum * sizeof(Elf64_Phdr),
                    (off_t)eh.e_phoff)) {
            for (const Elf64_Phdr &p : phdrs) {
                if (p.p_type == PT_LOAD) {
                    loads.push_back(LoadSeg{ p.p_vaddr, p.p_memsz, p.p_flags });
                }
            }
        }
    }

    /* 符号表选择对齐 Frida/GumTrace：**优先 .symtab**，只有当它一条都没枚举到
     * 时才回退到 .dynsym。gumelfmodule.c 的实现就是：
     *     gum_elf_module_enumerate_symbols_in_section (self, GUM_ELF_SECTION_SYMTAB, ...);
     *     if (ctx.count == 0)
     *       gum_elf_module_enumerate_dynamic_symbols (self, func, user_data);
     * 注意不是把两张表合并 —— 之前的实现先 dynsym 再 symtab 全收，
     * 与 GumTrace 的集合不同。 */
    size_t seen = 0;
    for (int pass = 0; pass < 2 && seen == 0; ++pass) {
        const uint32_t want = (pass == 0) ? SHT_SYMTAB : SHT_DYNSYM;
        for (const Elf64_Shdr &sh : shdrs) {
            if (sh.sh_type != want || sh.sh_link >= shdrs.size()) {
                continue;
            }
            const Elf64_Shdr &strtab = shdrs[sh.sh_link];
            if (strtab.sh_type != SHT_STRTAB) {
                continue;
            }
            seen += ingest_symtab(m, fd, sh, strtab, shdrs, loads);
        }
    }

    close(fd);

    if (m.syms.empty()) {
        return;
    }
    /* 同地址多符号时保留**最后**枚举到的那个，对齐 GumTrace：
     *   GumTrace 是 func_maps[details->address] = details->name;
     * （std::map 赋值），而 Frida 按 .symtab 文件顺序枚举，所以后者覆盖前者。
     * 这一步很关键：libc 的 .symtab 里映射符号与真实函数同地址 ——
     * 实测 free=0x47af8 同时有 $x.1(idx 113) 与 free(idx 6501)、
     * malloc=0x47c30 有 $x.5(124) 与 malloc(6503)、
     * pthread_mutex_lock=0xebba8 有 $x.9(6160) 与其本体(6512)、
     * strstr=0xce9e0 有 $x.0(4908) 与其本体(6527)。真实函数在 .symtab 里靠后，
     * 所以“后者胜”正好让真实函数名生效。
     * 之前的写法用 std::sort（不稳定）+ std::unique（保留每组第一个），
     * 同地址保留哪个是不确定的，实测把 free/malloc/pthread_mutex_lock/
     * strstr 等 14 个真实名字顶成了 $x.N。 */
    std::sort(m.syms.begin(), m.syms.end(),
              [](const SymEntry &a, const SymEntry &b) {
                  if (a.addr != b.addr) {
                      return a.addr < b.addr;
                  }
                  return a.seq > b.seq;   // seq 大的排在前，会被 unique 留下
              });
    m.syms.erase(std::unique(m.syms.begin(), m.syms.end(),
                             [](const SymEntry &a, const SymEntry &b) {
                                 return a.addr == b.addr;
                             }),
                 m.syms.end());
    LOGI("symbols: %s -> %zu syms", m.path.c_str(), m.syms.size());
}

// 查找包含 addr 的可执行映射对应的模块。
// g_mappings 已按 start 升序，用二分（不是线性扫描）——
// 本函数在**每条分支指令**上都可能被调用，而匿名区目标永远查不到，
// 线性扫 400+ 个映射是纯浪费。
const Module *module_for_addr(uint64_t addr, bool *need_parse, uint32_t *idx)
{
    auto it = std::upper_bound(g_mappings.begin(), g_mappings.end(), addr,
                               [](uint64_t v, const Mapping &m) { return v < m.start; });
    if (it == g_mappings.begin()) {
        return nullptr;
    }
    --it;
    if (addr < it->start || addr >= it->end) {
        return nullptr;
    }
    const Module &m = g_modules[it->module_idx];
    if (!m.parsed) {
        *need_parse = true;
        *idx = it->module_idx;
    }
    return &m;
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
