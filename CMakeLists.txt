cmake_minimum_required (VERSION 3.8)

project ("injector")

################################################################################
#
# Get Microsoft Visual Studio related paths:
#

execute_process(
    COMMAND "$ENV{ProgramFiles\(x86\)}\\Microsoft Visual Studio\\Installer\\vswhere.exe" "-latest" "-version" "[16.0,17.0)" "-property" "installationPath"
    OUTPUT_VARIABLE VS16_INSTALLPATH
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
string(REPLACE "\\" "/" VS16_INSTALLPATH ${VS16_INSTALLPATH})

execute_process(
    COMMAND "$ENV{ProgramFiles\(x86\)}\\Microsoft Visual Studio\\Installer\\vswhere.exe" "-latest" "-version" "[16.0,17.0)" "-requires" "Microsoft.Component.MSBuild" "-find" "MSBuild\\**\\**\\Bin\\MSBuild.exe"
    OUTPUT_VARIABLE VS16_MSBUILD
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
string(REPLACE "\\" "/" VS16_MSBUILD ${VS16_MSBUILD})


################################################################################


add_subdirectory("AfxHook")

set(CMAKE_INSTALL_PREFIX "${CMAKE_BINARY_DIR}/install")

add_custom_target(injector_x86
	DEPENDS afxhook
    WORKING_DIRECTORY ${injector_BINARY_DIR}
    BYPRODUCTS "${injector_BINARY_DIR}/injector.exe"
    COMMAND ${VS16_MSBUILD} "${injector_SOURCE_DIR}/injector.csproj" "-property:Configuration=Release" "-property:Platform=x86" "/p:OutDir=${injector_BINARY_DIR}/"
)

add_custom_target(injector_x64_dir
    WORKING_DIRECTORY ${injector_BINARY_DIR}
    COMMAND ${CMAKE_COMMAND} -E make_directory x64
)

add_custom_target(injector_x64
    DEPENDS injector_x64_dir afxhook_x64
    WORKING_DIRECTORY "${injector_BINARY_DIR}/x64"
    BYPRODUCTS "${injector_BINARY_DIR}/x64/injector.exe"
    COMMAND ${VS16_MSBUILD} "${injector_SOURCE_DIR}/injector.csproj" "-property:Configuration=Release" "-property:Platform=x64" "/p:OutDir=${injector_BINARY_DIR}/x64/"
)

add_custom_target(injector ALL
	DEPENDS injector_x86 injector_x64
)

install(
	PROGRAMS
		"${injector_BINARY_DIR}/injector.exe"
	DESTINATION ./
)
install(
	FILES
		"${afxhook_BINARY_DIR}/AfxHook.dat"
	DESTINATION ./
)

install(
	PROGRAMS
		"${injector_BINARY_DIR}/x64/injector.exe"
	DESTINATION ./x64
)
install(
	FILES
		"${afxhook_BINARY_DIR}/x64/AfxHook.dat"
	DESTINATION ./x64
)

set(CPACK_GENERATOR WIX)
set(CPACK_PACKAGE_NAME "HLAE Injector")
set(CPACK_PACKAGE_VENDOR "advancedfx.org")
set(CPACK_PACKAGE_VERSION_MAJOR 1)
set(CPACK_PACKAGE_VERSION_MINOR 0)
set(CPACK_PACKAGE_VERSION_PATCH 0)
set(CPACK_PACKAGE_INSTALL_DIRECTORY "HLAE")
set(CPACK_WIX_UPGRADE_GUID "0A9ADA4E-7FCB-4C5E-9BBF-7B97892ED9C3")
set(CPACK_WIX_TEMPLATE "${injector_SOURCE_DIR}/cmake/WIX.msm.template.in")
set(CPACK_PACKAGE_DIRECTORY ./bin)

include(CPack)

get_filename_component(CPACK_COMMAND ${CMAKE_COMMAND} PATH)
set(CPACK_COMMAND ${CPACK_COMMAND}/cpack)

add_custom_command(TARGET injector POST_BUILD
	COMMAND ${CMAKE_COMMAND} --install . -v
	COMMAND ${CPACK_COMMAND} -G WIX
	COMMAND ${CMAKE_COMMAND} -E rename ./bin/${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-win32.msi ./bin/${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-win32.msm
	COMMAND ${CMAKE_COMMAND} -E chdir ./bin ${CMAKE_COMMAND} -E sha512sum ${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-win32.msm > ./bin/${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-win32.msm.sha512
	WORKING_DIRECTORY ${CMAKE_BUILD_DIR}
)
