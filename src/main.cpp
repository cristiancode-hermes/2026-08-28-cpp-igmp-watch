// SPDX-License-Identifier: MIT
// cpp-igmp-watch — IPv4/IPv6 multicast group membership monitor (/proc/net/igmp, /proc/net/igmp6)
// Build: g++ -std=c++23 -O2 -Wall -Wextra src/main.cpp -o igmp-watch
// Usage: ./igmp-watch [--iface NAME] [--v4|--v6] [--users N] [--top N]
//                     [--watch N] [--json] [--demo] [--file PATH]
//                     [--no-names] [--no-color] [--selftest]

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

// ─────────────────────────────────────────────────────────────────────────────
// Mutable ANSI palette (--no-color must actually clear it)
// ─────────────────────────────────────────────────────────────────────────────
static std::string C_RESET   = "\x1b[0m";
static std::string C_BOLD    = "\x1b[1m";
static std::string C_DIM     = "\x1b[2m";
static std::string C_RED     = "\x1b[31m";
static std::string C_GREEN   = "\x1b[32m";
static std::string C_YELLOW  = "\x1b[33m";
static std::string C_BLUE    = "\x1b[34m";
static std::string C_CYAN    = "\x1b[36m";
static std::string C_MAGENTA = "\x1b[35m";

static void disable_color() {
  C_RESET = C_BOLD = C_DIM = C_RED = C_GREEN = C_YELLOW = C_BLUE = C_CYAN = C_MAGENTA = "";
}

// ─────────────────────────────────────────────────────────────────────────────
// Model
// ─────────────────────────────────────────────────────────────────────────────
struct Group {
  int iface = 0;            // interface index (ifindex)
  std::string device;       // interface name
  int proto = 0;            // 4 = IGMPv4 (/proc/net/igmp), 6 = MLDv2 (/proc/net/igmp6)
  std::string addr;         // formatted address, e.g. "224.0.0.251" or "ff02::fb"
  std::string raw;          // raw hex as printed by the kernel
  long users = 0;           // number of local users (sockets) on this group
  std::string timer;        // v4: "secs:jiffies_hex" as printed; v6: "0000000C" flags hex
  long reporter = -1;       // last reporter pid (-1 = not shown by kernel)
  std::string name;         // well-known name or ""
  std::string flags;        // v6 flags decoded (e.g. "TE|GS"); v4 empty

  bool is_v6() const { return proto == 6; }
};

struct Snapshot {
  long long ts = 0;
  std::vector<Group> groups;

  std::size_t count_v4() const {
    return static_cast<std::size_t>(
      std::count_if(groups.begin(), groups.end(), [](const Group& g) { return !g.is_v6(); }));
  }
  std::size_t count_v6() const {
    return static_cast<std::size_t>(
      std::count_if(groups.begin(), groups.end(), [](const Group& g) { return g.is_v6(); }));
  }
  std::size_t count_named() const {
    return static_cast<std::size_t>(
      std::count_if(groups.begin(), groups.end(), [](const Group& g) { return !g.name.empty(); }));
  }
  long total_users() const {
    long u = 0;
    for (const auto& g : groups) u += g.users;
    return u;
  }
  std::set<std::string> devices() const {
    std::set<std::string> d;
    for (const auto& g : groups) d.insert(g.device);
    return d;
  }
  std::map<std::string, std::size_t> by_name() const {
    std::map<std::string, std::size_t> m;
    for (const auto& g : groups) if (!g.name.empty()) ++m[g.name];
    return m;
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────
static long long now_secs() {
  return std::chrono::duration_cast<std::chrono::seconds>(
           std::chrono::system_clock::now().time_since_epoch()).count();
}

static std::optional<long long> parse_ll(std::string_view s, int base = 10) {
  auto start = s.find_first_not_of(" \t");
  if (start == std::string_view::npos) return std::nullopt;
  s.remove_prefix(start);
  long long v = 0;
  auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), v, base);
  if (ec != std::errc()) return std::nullopt;
  if (ptr != s.data() + s.size()) return std::nullopt;
  return v;
}

static std::string trim(std::string_view s) {
  while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
  while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r')) s.remove_suffix(1);
  return std::string(s);
}

static std::vector<std::string> split_ws(std::string_view s) {
  std::vector<std::string> out;
  std::istringstream ss{std::string(s)};
  std::string tok;
  while (ss >> tok) out.push_back(tok);
  return out;
}

static std::string pad(std::string s, std::size_t w) {
  if (s.size() >= w) return s;
  return s + std::string(w - s.size(), ' ');
}
static std::string padl(std::string s, std::size_t w) {
  if (s.size() >= w) return s;
  return std::string(w - s.size(), ' ') + s;
}

static std::string hex_to_bytes(std::string_view hex) {
  std::string out;
  for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
    long long b;
    if (auto v = parse_ll(hex.substr(i, 2), 16)) b = *v; else b = 0;
    out.push_back(static_cast<char>(b));
  }
  return out;
}

// /proc/net/igmp prints groups in REVERSE byte order (host-endian words).
static std::string fmt_ipv4(std::string_view hex) {
  std::string bytes = hex_to_bytes(hex);       // e.g. 01 00 00 E0
  if (bytes.size() != 4) return std::string(hex);
  std::ostringstream os;
  os << static_cast<unsigned>(static_cast<unsigned char>(bytes[3])) << "."
     << static_cast<unsigned>(static_cast<unsigned char>(bytes[2])) << "."
     << static_cast<unsigned>(static_cast<unsigned char>(bytes[1])) << "."
     << static_cast<unsigned>(static_cast<unsigned char>(bytes[0]));
  return os.str();
}

// Compress IPv6: 32 hex chars -> "ff02::1"
static std::string fmt_ipv6(std::string_view hex) {
  if (hex.size() != 32) return std::string(hex);
  std::vector<std::string> groups8;
  for (std::size_t i = 0; i < 32; i += 4) {
    std::string g = std::string(hex.substr(i, 4));
    // strip leading zeros within the group (keep at least one digit)
    auto z = g.find_first_not_of('0');
    groups8.push_back(z == std::string::npos ? "0" : g.substr(z));
  }
  // longest run of zero groups (>= 2)
  int best_start = -1, best_len = 0;
  int run_start = -1, run_len = 0;
  for (int i = 0; i < 8; ++i) {
    if (groups8[i] == "0") {
      if (run_start < 0) run_start = i;
      run_len = i - run_start + 1;
      if (run_len > best_len) { best_start = run_start; best_len = run_len; }
    } else {
      run_start = -1; run_len = 0;
    }
  }
  std::string out;
  bool skip_sep = false;
  for (int i = 0; i < 8; ++i) {
    if (best_len >= 2 && i == best_start) {
      out += "::";
      i += best_len - 1;
      skip_sep = true;
      continue;
    }
    if (i > 0 && !skip_sep) out += ":";
    skip_sep = false;
    out += groups8[i];
  }
  return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Well-known multicast group names
// ─────────────────────────────────────────────────────────────────────────────
static const char* group_name_v4(std::string_view addr) {
  if (addr == "224.0.0.1")    return "all-hosts";
  if (addr == "224.0.0.2")    return "all-routers";
  if (addr == "224.0.0.9")    return "RIP";
  if (addr == "224.0.0.22")   return "IGMP";
  if (addr == "224.0.0.251")  return "mDNS";
  if (addr == "224.0.0.252")  return "LLMNR";
  if (addr == "239.255.255.250") return "SSDP";
  if (addr == "224.0.0.18")   return "VRRP";
  return nullptr;
}
static const char* group_name_v6(std::string_view addr) {
  if (addr == "ff01::1" || addr == "ff02::1") return "all-nodes";
  if (addr == "ff02::2")     return "all-routers";
  if (addr == "ff02::fb")    return "mDNSv6";
  if (addr == "ff02::16")    return "MLDv2";
  if (addr == "ff02::c")     return "SSDP";
  if (addr == "ff02::1:3")   return "LLMNRv6";
  if (addr == "ff02::1:ff00:0") return "solicited-node";
  if (addr == "ff05::1:3")   return "site-LLMNR";
  return nullptr;
}

// /proc/net/igmp6 flags (net/ipv6/mcast.c)
static std::string decode_v6_flags(long f) {
  std::vector<std::string> names;
  if (f & 0x01) names.push_back("TE");       // transport endpoint
  if (f & 0x02) names.push_back("GS");       // group source? (REPORTING)
  if (f & 0x04) names.push_back("UNSOL");    // unsolicited report
  if (f & 0x08) names.push_back("RI");       // router interface? (SCHEDULER)
  if (names.empty()) return "";
  std::string out;
  for (std::size_t i = 0; i < names.size(); ++i) {
    if (i) out += "|";
    out += names[i];
  }
  return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// /proc/net/igmp parser (v4)
//   Idx	Device    : Count Querier	Group    Users Timer	Reporter
//   1	lo        :     1      V3
//   				010000E0     1 0:00000000		0
// ─────────────────────────────────────────────────────────────────────────────
static bool parse_igmp_file(const std::string& path, Snapshot& snap) {
  std::ifstream f(path);
  if (!f) return false;
  std::string line;
  int cur_iface = 0;
  std::string cur_dev;
  while (std::getline(f, line)) {
    std::string t = trim(line);
    if (t.empty() || t.starts_with('#')) continue;
    if (t.starts_with("Idx") || t.starts_with("Sl")) continue;  // header
    auto toks = split_ws(t);
    if (toks.size() >= 3 && toks[2] == ":") {
      // interface line: idx dev : count querier
      if (auto v = parse_ll(toks[0])) cur_iface = static_cast<int>(*v);
      cur_dev = toks[1];
      if (toks.size() >= 5 && toks[4] == "V2") {
        // keep querier version for summary? not stored per-group; nothing to do
      }
      continue;
    }
    // group line: hexaddr users timer [reporter]
    if (toks.size() < 3) continue;
    if (toks[0].size() != 8) continue;
    Group g;
    g.iface = cur_iface;
    g.device = cur_dev;
    g.proto = 4;
    g.raw = toks[0];
    g.addr = fmt_ipv4(toks[0]);
    if (auto v = parse_ll(toks[1])) g.users = *v;
    g.timer = toks[2];
    if (toks.size() >= 4)
      if (auto v = parse_ll(toks[3])) g.reporter = *v;
    if (const char* n = group_name_v4(g.addr)) g.name = n;
    snap.groups.push_back(std::move(g));
  }
  return true;
}

// /proc/net/igmp6 parser
//   idx iface addr(32hex) users flags reporter
static bool parse_igmp6_file(const std::string& path, Snapshot& snap) {
  std::ifstream f(path);
  if (!f) return false;
  std::string line;
  while (std::getline(f, line)) {
    std::string t = trim(line);
    if (t.empty() || t.starts_with('#')) continue;
    if (t.starts_with("idx")) continue;  // header
    auto toks = split_ws(t);
    if (toks.size() < 6) continue;
    if (toks[2].size() != 32) continue;
    Group g;
    if (auto v = parse_ll(toks[0])) g.iface = static_cast<int>(*v);
    g.device = toks[1];
    g.proto = 6;
    g.raw = toks[2];
    g.addr = fmt_ipv6(toks[2]);
    if (auto v = parse_ll(toks[3])) g.users = *v;
    g.timer = toks[4];
    if (auto v = parse_ll(toks[4], 16)) g.flags = decode_v6_flags(*v);
    if (toks.size() >= 6)
      if (auto v = parse_ll(toks[5])) g.reporter = *v;
    if (const char* n = group_name_v6(g.addr)) g.name = n;
    snap.groups.push_back(std::move(g));
  }
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Filters
// ─────────────────────────────────────────────────────────────────────────────
struct Filters {
  std::string iface;      // "" = all
  int proto = 0;          // 0 = both, 4 = v4 only, 6 = v6 only
  long min_users = 0;     // 0 = all
  int top = 0;
  bool names = true;
  bool demo = false;
  bool json = false;
  std::string file;       // "" = live /proc
  int watch = 0;
  bool color = true;
};

static bool passes(const Group& g, const Filters& f) {
  if (!f.iface.empty() && g.device != f.iface) return false;
  if (f.proto == 4 && g.is_v6()) return false;
  if (f.proto == 6 && !g.is_v6()) return false;
  if (f.min_users > 0 && g.users < f.min_users) return false;
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Load: choose data source and parse both files
// ─────────────────────────────────────────────────────────────────────────────
static bool load_snapshot(Snapshot& snap, const Filters& f, const std::string& igmp_path,
                          const std::string& igmp6_path) {
  snap.groups.clear();
  bool ok4 = true;
  if (!f.file.empty()) {
    ok4 = parse_igmp_file(f.file, snap);          // v4 dump (or combined handled below)
  } else {
    ok4 = parse_igmp_file(igmp_path, snap);
    parse_igmp6_file(igmp6_path, snap);
  }
  // stable order: v4 first then v6, sorted by iface then addr
  std::stable_sort(snap.groups.begin(), snap.groups.end(),
                   [](const Group& a, const Group& b) {
                     if (a.proto != b.proto) return a.proto < b.proto;
                     if (a.iface != b.iface) return a.iface < b.iface;
                     return a.addr < b.addr;
                   });
  return ok4;
}

// ─────────────────────────────────────────────────────────────────────────────
// Render (terminal table)
// ─────────────────────────────────────────────────────────────────────────────
static std::string proto_color(const Group& g) {
  return g.is_v6() ? C_CYAN : C_GREEN;
}

static void render_snapshot(const Snapshot& snap, const Filters& f, bool watch_mode) {
  std::size_t shown = 0;
  std::size_t total_shown = 0;
  for (const auto& g : snap.groups) if (passes(g, f)) ++total_shown;

  std::cout << C_BOLD << "  Multicast group membership  /proc/net/igmp + igmp6" << C_RESET << "   "
            << C_DIM << snap.groups.size() << " groups · " << snap.total_users() << " users"
            << C_RESET << "\n";
  std::cout << C_DIM << "  iface        group              users  timer        reporter  flags  name" << C_RESET << "\n";
  std::cout << C_DIM << "  " << std::string(86, '-') << C_RESET << "\n";

  for (const auto& g : snap.groups) {
    if (!passes(g, f)) continue;
    if (f.top > 0 && shown >= static_cast<std::size_t>(f.top)) break;
    ++shown;
    std::string iface_s = g.device.empty() ? std::to_string(g.iface) : g.device;
    std::string timer_s = g.is_v6() ? g.timer : g.timer;
    std::string rep = g.reporter >= 0 ? std::to_string(g.reporter) : "-";
    std::string flags_s = g.is_v6() ? (g.flags.empty() ? "-" : g.flags) : "-";
    std::string name_s = g.name.empty() ? "" : g.name;
    if (!f.names) name_s = "";

    std::cout << "  " << pad(iface_s, 9) << "  "
              << proto_color(g) << pad(g.addr, 20) << C_RESET << "  "
              << padl(std::to_string(g.users), 2) << "    "
              << pad(timer_s, 12) << "  "
              << pad(rep, 4) << "  "
              << pad(flags_s, 9) << "  "
              << (name_s.empty() ? C_DIM : C_YELLOW) << name_s << C_RESET << "\n";
  }

  auto devs = snap.devices();
  std::cout << "\n  " << C_DIM << "ifaces: " << C_RESET;
  bool first = true;
  for (const auto& d : devs) {
    if (!first) std::cout << C_DIM << ", " << C_RESET;
    first = false;
    std::size_t n = static_cast<std::size_t>(
      std::count_if(snap.groups.begin(), snap.groups.end(),
                    [&](const Group& g) { return g.device == d; }));
    std::cout << C_BLUE << d << C_RESET << "(" << n << ")";
  }
  auto names = snap.by_name();
  std::cout << "\n" << C_DIM << "  v4: " << C_RESET << snap.count_v4()
            << C_DIM << "  v6: " << C_RESET << snap.count_v6()
            << C_DIM << "  named: " << C_RESET << snap.count_named();
  if (!names.empty()) {
    std::cout << C_DIM << "  · " << C_RESET;
    first = true;
    for (const auto& [n, c] : names) {
      if (!first) std::cout << C_DIM << ", " << C_RESET;
      first = false;
      std::cout << C_MAGENTA << n << C_RESET << "(" << c << ")";
    }
  }
  std::cout << C_DIM << "  ·  shown: " << C_RESET << shown << "/" << total_shown << "\n";
  if (watch_mode) std::cout << C_DIM << "  ts=" << snap.ts << C_RESET << "\n";
  std::cout << "\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// JSON output
// ─────────────────────────────────────────────────────────────────────────────
static void render_json(std::ostream& os, const Snapshot& snap, bool demo) {
  os << "{\n  \"summary\": {\n";
  os << "    \"ts\": " << snap.ts << ",\n";
  os << "    \"total\": " << snap.groups.size() << ",\n";
  os << "    \"v4\": " << snap.count_v4() << ",\n";
  os << "    \"v6\": " << snap.count_v6() << ",\n";
  os << "    \"users\": " << snap.total_users() << ",\n";
  os << "    \"demo\": " << (demo ? "true" : "false") << "\n";
  os << "  },\n  \"groups\": [\n";
  bool first = true;
  for (const auto& g : snap.groups) {
    if (!first) os << ",\n";
    first = false;
    os << "    {\"iface\": " << g.iface << ", \"device\": \"" << g.device
       << "\", \"proto\": " << g.proto << ", \"addr\": \"" << g.addr
       << "\", \"name\": \"" << g.name << "\", \"users\": " << g.users
       << ", \"timer\": \"" << g.timer << "\", \"reporter\": " << g.reporter
       << ", \"flags\": \"" << (g.is_v6() ? g.flags : "") << "\"}";
  }
  os << "\n  ]\n}\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// Demo datasets (synthetic: office NIC + wifi + docker bridge + LAN bridge)
// ─────────────────────────────────────────────────────────────────────────────
static bool dump_to_file(const std::string& path, const std::string& content) {
  std::ofstream f(path);
  if (!f) return false;
  f << content;
  return true;
}

static const char* DEMO_IGMP =
  "Idx\tDevice    : Count Querier\tGroup    Users Timer\tReporter\n"
  "# loopback — all-hosts only\n"
  "1\tlo        :     1      V3\n"
  "\t\t\t\t010000E0     1 0:00000000\t\t0\n"
  "# office NIC: all-hosts + mDNS + IGMP + SSDP (reporter + timer running)\n"
  "2\teth0      :     4      V3\n"
  "\t\t\t\t010000E0     1 0:00000000\t\t0\n"
  "\t\t\t\tFB0000E0     2 0:00000000\t\t0\n"
  "\t\t\t\t160000E0     1 0:00000000\t\t0\n"
  "\t\t\t\tFAFFFFEF     3 1:00000A00\t\t1\n"
  "# wifi: mDNS (2 sockets) + LLMNR, IGMPv2 querier\n"
  "3\twlan0     :     2      V2\n"
  "\t\t\t\tFB0000E0     4 0:00000000\t\t0\n"
  "\t\t\t\tFC0000E0     1 0:00000000\t\t0\n"
  "# docker bridge: all-hosts only\n"
  "4\tdocker0   :     1      V3\n"
  "\t\t\t\t010000E0     1 0:00000000\t\t0\n"
  "# LAN bridge: all-routers + IGMP + RIP\n"
  "5\tbr-lan    :     3      V3\n"
  "\t\t\t\t020000E0     1 0:00000000\t\t0\n"
  "\t\t\t\t160000E0     1 0:00000000\t\t0\n"
  "\t\t\t\t090000E0     1 0:00000000\t\t0\n";

static const char* DEMO_IGMP6 =
  "# IPv6 multicast memberships (/proc/net/igmp6)\n"
  "1    lo              ff020000000000000000000000000001     1 0000000C 0\n"
  "1    lo              ff010000000000000000000000000001     1 00000008 0\n"
  "2    eth0            ff020000000000000000000000000001     1 0000000C 0\n"
  "2    eth0            ff010000000000000000000000000001     1 00000008 0\n"
  "2    eth0            ff0200000000000000000000000000fb     2 00000004 0\n"
  "2    eth0            ff020000000000000000000000000016     1 00000004 0\n"
  "3    wlan0           ff020000000000000000000000000001     1 0000000C 0\n"
  "3    wlan0           ff0200000000000000000000000000fb     3 00000004 1\n";

static bool demo_load(Snapshot& snap) {
  std::string p4 = "/tmp/igmp-demo.table";
  std::string p6 = "/tmp/igmp6-demo.table";
  if (!dump_to_file(p4, DEMO_IGMP)) return false;
  if (!dump_to_file(p6, DEMO_IGMP6)) return false;
  snap.groups.clear();
  bool ok = parse_igmp_file(p4, snap);
  ok = parse_igmp6_file(p6, snap) && ok;
  std::stable_sort(snap.groups.begin(), snap.groups.end(),
                   [](const Group& a, const Group& b) {
                     if (a.proto != b.proto) return a.proto < b.proto;
                     if (a.iface != b.iface) return a.iface < b.iface;
                     return a.addr < b.addr;
                   });
  std::remove(p4.c_str());
  std::remove(p6.c_str());
  return ok;
}

// ─────────────────────────────────────────────────────────────────────────────
// Watch mode (periodic refresh with join/leave deltas)
// ─────────────────────────────────────────────────────────────────────────────
static std::string group_key(const Group& g) {
  return g.raw + "|" + g.device + "|" + std::to_string(g.proto);
}

static void render_delta(const Snapshot& prev, const Snapshot& cur, const Filters& f) {
  std::set<std::string> prev_ids, cur_ids;
  for (const auto& g : prev.groups) if (passes(g, f)) prev_ids.insert(group_key(g));
  for (const auto& g : cur.groups) if (passes(g, f)) cur_ids.insert(group_key(g));
  std::vector<std::string> added, removed;
  for (const auto& k : cur_ids) if (!prev_ids.contains(k)) added.push_back(k);
  for (const auto& k : prev_ids) if (!cur_ids.contains(k)) removed.push_back(k);
  std::cout << C_DIM << "  delta vs previous: "
            << C_GREEN << "+" << added.size() << " joined   "
            << C_RED << "-" << removed.size() << " left   "
            << C_CYAN << "total " << cur.groups.size() << C_RESET
            << (added.empty() && removed.empty() ? "  (stable)" : "") << "\n\n";
  std::cout << std::flush;  // watch loops: never lose frames on pipes
}

// ─────────────────────────────────────────────────────────────────────────────
// Selftest (ad-hoc truth for this binary)
// ─────────────────────────────────────────────────────────────────────────────
static int g_pass = 0, g_fail = 0;
static void check(bool ok, const std::string& what) {
  if (ok) { ++g_pass; } else { ++g_fail; std::cout << "    FAIL  " << what << "\n"; }
}

static int selftest() {
  std::cout << "== byte/hex helpers ==\n";
  check(hex_to_bytes("010000E0").size() == 4, "hex_to_bytes 4 bytes");
  check(fmt_ipv4("010000E0") == "224.0.0.1", "v4 reverse order 010000E0 -> 224.0.0.1");
  check(fmt_ipv4("FB0000E0") == "224.0.0.251", "v4 mDNS FB0000E0 -> 224.0.0.251");
  check(fmt_ipv4("160000E0") == "224.0.0.22", "v4 IGMP 160000E0 -> 224.0.0.22");
  check(fmt_ipv4("FAFFFFEF") == "239.255.255.250", "v4 SSDP FAFFFFEF -> 239.255.255.250");
  check(fmt_ipv6("ff020000000000000000000000000001") == "ff02::1", "v6 ff02::1");
  check(fmt_ipv6("ff010000000000000000000000000001") == "ff01::1", "v6 ff01::1");
  check(fmt_ipv6("ff0200000000000000000000000000fb") == "ff02::fb", "v6 ff02::fb");
  check(fmt_ipv6("ff050000000000000000000000010003") == "ff05::1:3", "v6 ff05::1:3");
  check(fmt_ipv6("ff0200000000000000000001ff000000") == "ff02::1:ff00:0", "v6 solicited-node");
  check(fmt_ipv6("ff020000000000000000000000000016") == "ff02::16", "v6 ff02::16 (MLDv2)");
  check(fmt_ipv6("20010db8000000000000000000000001") == "2001:db8::1", "v6 2001:db8::1");
  check(fmt_ipv6("20010db8000000000000000000010002") == "2001:db8::1:2", "v6 2001:db8::1:2");

  std::cout << "== names ==\n";
  check(std::string(group_name_v4("224.0.0.251")) == "mDNS", "name mDNS");
  check(std::string(group_name_v6("ff02::fb")) == "mDNSv6", "name mDNSv6");
  check(group_name_v4("224.0.0.99") == nullptr, "unknown v4 has no name");
  check(decode_v6_flags(0x0C) == "UNSOL|RI", "v6 flags 0x0C -> UNSOL|RI");
  check(decode_v6_flags(0x00) == "", "v6 flags 0 empty");

  std::cout << "== v4 parser (synthetic dump, comments tolerated) ==\n";
  {
    std::string dump =
      "Idx\tDevice    : Count Querier\tGroup    Users Timer\tReporter\n"
      "# comment line tolerated\n"
      "1\tlo        :     1      V3\n"
      "\t\t\t\t010000E0     1 0:00000000\t\t0\n"
      "2\teth0      :     2      V3\n"
      "\t\t\t\tFB0000E0     2 0:00000000\t\t0\n"
      "\t\t\t\tFAFFFFEF     3 1:00000A00\t\t1\n";
    std::string path = "/tmp/igmp-selftest-v4.table";
    Snapshot s;
    check(dump_to_file(path, dump), "writes v4 dump");
    check(parse_igmp_file(path, s), "parses v4 dump");
    std::remove(path.c_str());
    check(s.groups.size() == 3, "3 v4 groups parsed");
    if (s.groups.size() == 3) {
      check(s.groups[0].device == "lo" && s.groups[0].iface == 1, "group[0] on lo iface 1");
      check(s.groups[0].addr == "224.0.0.1" && s.groups[0].users == 1, "group[0] all-hosts users=1");
      check(s.groups[0].name == "all-hosts", "group[0] named all-hosts");
      check(s.groups[0].timer == "0:00000000", "group[0] timer raw");
      check(s.groups[0].reporter == 0, "group[0] reporter 0");
      check(s.groups[1].addr == "224.0.0.251" && s.groups[1].users == 2, "group[1] mDNS users=2");
      check(s.groups[1].name == "mDNS", "group[1] named mDNS");
      check(s.groups[2].addr == "239.255.255.250" && s.groups[2].reporter == 1,
            "group[2] SSDP reporter=1");
      check(s.groups[2].name == "SSDP", "group[2] named SSDP");
    }
  }

  std::cout << "== v6 parser (synthetic dump) ==\n";
  {
    std::string dump =
      "idx iface addr(32hex) users flags reporter\n"
      "1    lo              ff020000000000000000000000000001     1 0000000C 0\n"
      "2    eth0            ff0200000000000000000000000000fb     2 00000004 1\n";
    std::string path = "/tmp/igmp-selftest-v6.table";
    Snapshot s;
    check(dump_to_file(path, dump), "writes v6 dump");
    check(parse_igmp6_file(path, s), "parses v6 dump");
    std::remove(path.c_str());
    check(s.groups.size() == 2, "2 v6 groups parsed");
    if (s.groups.size() == 2) {
      check(s.groups[0].addr == "ff02::1" && s.groups[0].device == "lo", "v6 ff02::1 on lo");
      check(s.groups[0].name == "all-nodes", "v6 named all-nodes");
      check(s.groups[0].flags == "UNSOL|RI", "v6 flags decoded");
      check(s.groups[1].addr == "ff02::fb" && s.groups[1].users == 2, "v6 ff02::fb users=2");
      check(s.groups[1].name == "mDNSv6" && s.groups[1].reporter == 1, "v6 mDNSv6 reporter=1");
    }
  }

  std::cout << "== real /proc (tolerant) ==\n";
  {
    Snapshot s;
    check(parse_igmp_file("/proc/net/igmp", s), "reads real /proc/net/igmp");
    std::vector<Group> v6s;
    Snapshot s6;
    check(parse_igmp6_file("/proc/net/igmp6", s6), "reads real /proc/net/igmp6");
    if (!s.groups.empty()) {
      bool ok_dev = true;
      for (const auto& g : s.groups) if (g.device.empty()) ok_dev = false;
      check(ok_dev, "all real v4 groups have a device");
      check(s.count_v4() == s.groups.size(), "v4 count consistent");
    } else {
      std::cout << "  INFO  host has no v4 memberships\n";
      check(true, "sparse v4 host tolerated");
    }
    check(s6.groups.size() >= 1, "host has at least the loopback v6 groups");
  }

  std::cout << "== filters ==\n";
  {
    Snapshot s;
    check(demo_load(s), "demo loads");
    Filters f;
    f.iface = "eth0";
    int n = 0;
    for (const auto& g : s.groups) if (passes(g, f)) ++n;
    check(n == 8, "demo eth0 == 8 groups (4 v4 + 4 v6)");
    f = Filters{}; f.proto = 6;
    n = 0;
    for (const auto& g : s.groups) if (passes(g, f)) ++n;
    check(n == 8, "demo v6 == 8 groups");
    f = Filters{}; f.proto = 4;
    n = 0;
    for (const auto& g : s.groups) if (passes(g, f)) ++n;
    check(n == 11, "demo v4 == 11 groups");
    f = Filters{}; f.min_users = 2;
    n = 0;
    for (const auto& g : s.groups) if (passes(g, f)) ++n;
    check(n == 5, "demo users>=2 == 5 groups");
    f = Filters{}; f.iface = "wlan0"; f.proto = 6;
    n = 0;
    for (const auto& g : s.groups) if (passes(g, f)) ++n;
    check(n == 2, "demo wlan0 v6 == 2 groups");
  }

  std::cout << "== demo summary ==\n";
  {
    Snapshot s;
    check(demo_load(s), "demo reloads");
    check(s.groups.size() == 19, "demo total 19 groups (11 v4 + 8 v6)");
    check(s.count_v4() == 11, "demo 11 v4");
    check(s.count_v6() == 8, "demo 8 v6");
    check(s.total_users() == 28, "demo total users == 28");
    check(s.count_named() == 19, "demo 19 named groups");
    check(s.devices().size() == 5, "demo 5 ifaces");
    auto names = s.by_name();
    check(names["mDNS"] == 2 && names["mDNSv6"] == 2, "demo mDNS 2 + mDNSv6 2");
    check(names["SSDP"] == 1, "demo SSDP 1");
    check(names["all-hosts"] == 3, "demo all-hosts 3");
    check(names["all-nodes"] == 5, "demo all-nodes 5 (v6)");
    check(names["all-routers"] == 1, "demo all-routers 1");
    check(names["IGMP"] == 2, "demo IGMP 2");
  }

  std::cout << "== JSON validity ==\n";
  {
    Snapshot s;
    s.ts = 1785117430;
    check(demo_load(s), "demo for json");
    std::ostringstream os;
    render_json(os, s, true);
    std::string j = os.str();
    check(j.starts_with("{\n  \"summary\": {"), "json starts with quoted summary key");
    check(j.find("\"groups\": [") != std::string::npos, "json has quoted groups array");
    check(j.find("\"addr\": \"224.0.0.251\"") != std::string::npos, "json addr quoted");
    check(j.find("\"name\": \"mDNS\"") != std::string::npos, "json name quoted");
    check(std::count(j.begin(), j.end(), '{') == std::count(j.begin(), j.end(), '}'),
          "json braces balanced");
    check(j.rfind("}") == j.size() - 2, "json ends with closing brace");
  }

  std::cout << "\nRESULT: " << g_pass << " passed, " << g_fail << " failed\n";
  return g_fail == 0 ? 0 : 1;
}

// ─────────────────────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────────────────────
static void usage() {
  std::cout <<
    "Usage: ./igmp-watch [options]\n"
    "  IPv4/IPv6 multicast group membership monitor — /proc/net/igmp + /proc/net/igmp6\n"
    "\n"
    "  --iface NAME         only groups on that interface (e.g. eth0, wlan0)\n"
    "  --v4                 only IPv4 memberships (/proc/net/igmp)\n"
    "  --v6                 only IPv6 memberships (/proc/net/igmp6)\n"
    "  --users N            only groups with at least N local users\n"
    "  --top N              show only the first N groups\n"
    "  --watch N            refresh every N seconds, printing join/leave deltas\n"
    "  --json               machine-readable JSON output\n"
    "  --demo               synthetic demo (office + wifi + docker + LAN bridge)\n"
    "  --file PATH          parse a /proc/net/igmp dump instead of /proc (tolerates #)\n"
    "  --no-names           hide well-known group names\n"
    "  --no-color           disable ANSI colors (0 escapes in pipes)\n"
    "  --selftest           run self-tests\n"
    "  -h, --help           show this help\n";
}

int main(int argc, char** argv) {
  Filters f;
  for (int i = 1; i < argc; ++i) {
    std::string_view a{argv[i]};
    auto next_val = [&](const char* flag) -> std::optional<std::string> {
      if (i + 1 < argc) { ++i; return std::string(argv[i]); }
      std::cerr << "Missing value for " << flag << "\n";
      return std::nullopt;
    };
    if (a == "-h" || a == "--help")  { usage(); return 0; }
    else if (a == "--selftest")      { return selftest(); }
    else if (a == "--no-color")      { f.color = false; disable_color(); }
    else if (a == "--json")          { f.json = true; }
    else if (a == "--demo")          { f.demo = true; }
    else if (a == "--v4")            { f.proto = 4; }
    else if (a == "--v6")            { f.proto = 6; }
    else if (a == "--no-names")      { f.names = false; }
    else if (a == "--iface") {
      auto v = next_val("--iface"); if (!v) return 2;
      f.iface = *v;
    }
    else if (a == "--users") {
      auto v = next_val("--users"); if (!v) return 2;
      if (auto n = parse_ll(*v)) f.min_users = *n; else { std::cerr << "Bad --users\n"; return 2; }
    }
    else if (a == "--top") {
      auto v = next_val("--top"); if (!v) return 2;
      if (auto n = parse_ll(*v)) f.top = static_cast<int>(*n); else { std::cerr << "Bad --top\n"; return 2; }
    }
    else if (a == "--watch") {
      auto v = next_val("--watch"); if (!v) return 2;
      if (auto n = parse_ll(*v)) f.watch = static_cast<int>(*n); else { std::cerr << "Bad --watch\n"; return 2; }
      if (f.watch <= 0) f.watch = 0;
    }
    else if (a == "--file") {
      auto v = next_val("--file"); if (!v) return 2;
      f.file = *v;
    }
    else { std::cerr << "Unknown option: " << a << "\n"; usage(); return 2; }
  }

  if (f.watch > 0) {
    Snapshot prev, cur;
    auto load = [&](Snapshot& s) {
      return f.demo ? demo_load(s) : load_snapshot(s, f, "/proc/net/igmp", "/proc/net/igmp6");
    };
    load(prev);
    for (;;) {
      load(cur);
      cur.ts = now_secs();
      render_snapshot(cur, f, true);
      render_delta(prev, cur, f);
      prev = std::move(cur);
      std::this_thread::sleep_for(std::chrono::seconds(static_cast<unsigned>(f.watch)));
    }
  }

  Snapshot s;
  if (f.demo) {
    if (!demo_load(s)) { std::cerr << "Cannot build demo dataset\n"; return 1; }
  } else if (!f.file.empty()) {
    if (!parse_igmp_file(f.file, s)) { std::cerr << "Cannot open " << f.file << "\n"; return 1; }
  } else {
    if (!load_snapshot(s, f, "/proc/net/igmp", "/proc/net/igmp6")) {
      std::cerr << "Cannot open /proc/net/igmp\n"; return 1;
    }
  }
  s.ts = now_secs();
  if (f.json) render_json(std::cout, s, f.demo);
  else        render_snapshot(s, f, false);
  return 0;
}