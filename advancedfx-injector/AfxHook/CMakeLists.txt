cmake_minimum_required (VERSION 3.15)

project ("afxhook")

if("${CMAKE_GENERATOR_PLATFORM}" STREQUAL "Win32")
set(AFX_HOOK_SOURCE_FILE "AfxHook_586.asm")
else()
set(AFX_HOOK_SOURCE_FILE "AfxHook_x64.asm")
endif()

add_custom_command(
	WORKING_DIRECTORY ${afxhook_BINARY_DIR}
	OUTPUT "${afxhook_BINARY_DIR}/AfxHook.dat"
	COMMAND nasm.exe  -f bin -o "${afxhook_BINARY_DIR}/AfxHook.dat" "${afxhook_SOURCE_DIR}/${AFX_HOOK_SOURCE_FILE}"
	DEPENDS "${afxhook_SOURCE_DIR}/${AFX_HOOK_SOURCE_FILE}"
)

add_custom_target(afxhook
	DEPENDS "${afxhook_BINARY_DIR}/AfxHook.dat"
)