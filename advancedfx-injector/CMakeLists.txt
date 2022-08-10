cmake_minimum_required (VERSION 3.15)

project (advancedfx-injector LANGUAGES CXX C)

add_subdirectory("AfxHook")

add_custom_command(
    WORKING_DIRECTORY ${afxhook_BINARY_DIR}
    OUTPUT "${advancedfx-injector_BINARY_DIR}/afxhook.o"
    COMMAND ld -r -b binary -o "${advancedfx-injector_BINARY_DIR}/afxhook.o" AfxHook.dat
    DEPENDS afxhook)

add_definitions(
    "-D_UNICODE"
    "-DUNICODE"
)

add_executable(${PROJECT_NAME}
    "main.cpp"
    "afxhook.o"
)
target_link_options(
    ${PROJECT_NAME} PRIVATE -municode
)

install(TARGETS ${PROJECT_NAME} DESTINATION bin)