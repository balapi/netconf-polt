# TR-451 pOLT vendor interface
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/bcm)
    bcm_add_subdirectory(bcm)
else()
    bcm_add_subdirectory(sim)
endif()
