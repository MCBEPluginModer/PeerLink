set_project("messenger")
set_version("1.0.0")
set_languages("cxx20")

target("messenger")
    set_kind("binary")
    add_files("src/*.cpp")
    add_files("src/core/*.cpp")
    add_files("src/net/*.cpp")
    add_files("src/crypto/*.cpp")
    add_includedirs("src")

    if is_plat("windows") then
        add_syslinks("ws2_32", "advapi32")
        add_defines("_WIN32_WINNT=0x0601", "NOMINMAX")
    end