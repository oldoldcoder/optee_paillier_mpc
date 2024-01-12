project (paillier C)

set (SRC host/main.c)

add_executable (${PROJECT_NAME} ${SRC})
find_package(mbedtls)
target_include_directories(${PROJECT_NAME}
			   PRIVATE ta/include
			   PRIVATE include)

target_link_libraries (${PROJECT_NAME} PRIVATE teec 

PRIVATE mbedtls

PRIVATE mbedx509

PRIVATE mbedcrypto
)

install (TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
