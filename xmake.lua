set_project("PeerLink")
set_version("0.4.0")

set_languages("cxx20")
set_warnings("all", "extra")
if is_mode("release") then
    set_optimize("fastest")
end

target("messenger")
    set_kind("binary")
    add_files("src/*.cpp", "src/core/*.cpp", "src/crypto/*.cpp", "src/net/*.cpp", "src/reliability/*.cpp", "src/ui/*.cpp")
    remove_files("src/fuzz/*.cpp")
    add_includedirs("src")
    add_syslinks("ws2_32", "crypt32", "advapi32")

target("fuzz_packet_protocol")
    set_kind("binary")
    add_files("src/fuzz/fuzz_packet_protocol.cpp", "src/net/packet_protocol.cpp", "src/core/utils.cpp", "src/core/logger.cpp")
    add_includedirs("src")
    add_defines("P2P_FUZZ_STANDALONE")
    add_syslinks("ws2_32", "crypt32", "advapi32")
