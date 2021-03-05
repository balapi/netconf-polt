# Top level CMakeLists.txt defining the build project for the BCM68620 products

#====
# Indicate the minimum version of CMake required
#====
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

#====
# Identify where to find the modules
#====
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules)

#====
# Set a project version. Really doesn't matter what we use here, but it could be release related if we want
#====
set(PROJECT_VERSION 3.0.0)

#====
# Define the project we are building for
#====
project(bcm686xx
        VERSION ${PROJECT_VERSION}
        LANGUAGES CXX C ASM)

#====
# Set global variables used here
#====
set(SOURCE_TOP ${CMAKE_CURRENT_SOURCE_DIR})
set(BUILD_TOP ${CMAKE_CURRENT_BINARY_DIR})
set(CMAKE_INSTALL_PREFIX ${BUILD_TOP})
set(BAL_API_EXTERNAL_OS_ABSTRACTION TRUE)

#====
# Add the CMake modules we use here
#====
include(utils)
include(common_definitions)
include(build_macros)
include(protoc_codegen_macros)     # Macros supporting code generation from .proto and building the generation files
include(optional_macros)           # Include any optional macros used for internal testing
include(third_party)               # Macros for downloading & building third-party libraries

#====
# Add the top level subdirectories we need to add
#====
bcm_add_subdirectory(daemon)
bcm_add_subdirectory(third_party)
bcm_add_subdirectory(onu_mgmt)
bcm_add_subdirectory(netconf_server)
bcm_add_subdirectory(balapi)

#====
# Post processing support to make the custom properties transitive
#====
include(post_process)
bcm_flatten_transitive_dependencies()
