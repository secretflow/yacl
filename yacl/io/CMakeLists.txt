set(YACL_SOURCE_FILES ${YACL_SOURCE_FILES})

add_subdirectory(stream)
add_subdirectory(rw)

set(YACL_SOURCE_FILES ${YACL_SOURCE_FILES} PARENT_SCOPE)
