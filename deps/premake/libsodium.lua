libsodium = {
	source = path.join(dependencies.basePath, "libsodium"),
}

function libsodium.import()
	links {"libsodium"}

	libsodium.includes()
end

function libsodium.includes()
	includedirs {
		path.join(libsodium.source, "src/libsodium/include")
	}
	
	defines {
		"SODIUM_STATIC=1",
		"SODIUM_EXPORT="
	}
end

function libsodium.project()
	project "libsodium"
		language "C"

		libsodium.includes()
		
		includedirs {
			path.join(libsodium.source, "src/libsodium/include/sodium"),
		}

		files {
			path.join(libsodium.source, "src/**.c"),
			path.join(libsodium.source, "src/**.h")
		}

		defines {
			"_CRT_SECURE_NO_WARNINGS",
			"NATIVE_LITTLE_ENDIAN"
		}

		prebuildcommands { -- This is hacky, but like ¯\_(ツ)_/¯
			"{COPYFILE} %{wks.location}..\\deps\\libsodium\\builds\\msvc\\version.h %{wks.location}..\\deps\\libsodium\\src\\libsodium\\include\\sodium"
		}

		warnings "Off"
		kind "StaticLib"
end

table.insert(dependencies, libsodium)
