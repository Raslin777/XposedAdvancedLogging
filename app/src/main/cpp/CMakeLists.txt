cmake_minimum_required(VERSION 3.4.1)

add_library(xposedjnihook SHARED
            hookers.c)

# Include libraries needed for lib
target_link_libraries(xposedjnihook
                      android
					  log)
