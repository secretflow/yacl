set(YACL_SOURCE_FILES ${YACL_SOURCE_FILES})

add_subdirectory(msgpack)
add_subdirectory(rw)
add_subdirectory(stream)

set(YACL_SOURCE_FILES ${YACL_SOURCE_FILES} PARENT_SCOPE)
