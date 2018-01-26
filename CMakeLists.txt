#
#  This source code is part of oathuri, a free OATH key URI generator program
#  Copyright (C) 2017  Zoltan Puskas <zoltan@sinustrom.info>
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
CMAKE_MINIMUM_REQUIRED(VERSION 3.6)

PROJECT(
    oath-uri
    LANGUAGES C
    VERSION 1.0.0
    DESCRIPTION "Oath Key URI generator library and CLI"
)

## CMake settings
SET( CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin" )
SET( CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib" )

SET( CMAKE_C_FLAGS_RELEASE "-O3" )
SET( CMAKE_C_FLAGS_DEBUG "-g -ggdb" )

# By default build release binaries
IF(NOT CMAKE_BUILD_TYPE)
    SET( CMAKE_BUILD_TYPE "Release" )
ENDIF(NOT CMAKE_BUILD_TYPE)


## Feature switches
OPTION( OATHURI_CLI "Build command line interface" ON )

## Compiler settings
FIND_PACKAGE( CURL 7.15.4 REQUIRED )

# Add -Werror once implementation is beyond skeleton phase
ADD_DEFINITIONS( -std=c99 -pedantic -fsigned-char -freg-struct-return
                 -Wall -W -Wshadow -Wstrict-prototypes -Wpointer-arith
                 -Wcast-qual -Winline )
INCLUDE_DIRECTORIES ( liboathuri ${CURL_INCLUDE_DIRS} )

## Library target
ADD_LIBRARY ( oathuri-lib SHARED liboathuri/urigen.c )

SET_TARGET_PROPERTIES(
    oathuri-lib PROPERTIES
    OUTPUT_NAME oathuri
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
    PUBLIC_HEADER liboathuri/oathuri.h
)

TARGET_LINK_LIBRARIES( oathuri-lib PUBLIC ${CURL_LIBRARIES} )

INSTALL( TARGETS oathuri-lib LIBRARY DESTINATION lib )
INSTALL( FILES liboathuri/oathuri.h DESTINATION include )
INSTALL(
    FILES 
    man/oathuri.h.3
    man/oathuri_hotp_generate.3
    man/oathuri_totp_generate.3
    DESTINATION ${CMAKE_INSTALL_PREFIX}/share/man/man3
)


## CLI target
IF(OATHURI_CLI)
    ADD_EXECUTABLE ( oathuri-bin oathuri/oathuri.c )

    SET_TARGET_PROPERTIES( oathuri-bin PROPERTIES OUTPUT_NAME oathuri )

    TARGET_LINK_LIBRARIES ( oathuri-bin PUBLIC oathuri-lib )

    INSTALL(
        TARGETS oathuri-bin
        RUNTIME DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
    )
    INSTALL(
        FILES man/oathuri.1
        DESTINATION ${CMAKE_INSTALL_PREFIX}/share/man/man1
    )
ENDIF(OATHURI_CLI)
