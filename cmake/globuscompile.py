#!/usr/bin/python

#******************************************************************************
# Utility to help finding out globus location
#
# @author Sebastien Ponce sebastien.ponce@cern.ch
#******************************************************************************

# Modules
import platform
import string
import sys
import os
import re
import getopt

# globus flavour
(bits, linkage) = platform.architecture()
if bits == '64bit':
    FLAVOUR = 'gcc64dbg'
else:
    FLAVOUR = 'gcc32dbg'

# Constants
INCDIRS = [os.sep.join(['', 'opt', 'globus', 'include', FLAVOUR]), 
           os.sep.join(['', 'usr', 'include', 'globus']),
           os.sep.join(['', 'usr', 'lib64', 'globus', 'include']),
           os.sep.join(['', 'usr', 'lib', 'globus', 'include'])]
LIBDIRS = [os.sep.join(['', 'opt', 'globus', 'lib']), 
           os.sep.join(['', 'usr', 'lib64']), 
           os.sep.join(['', 'usr', 'lib'])]
if os.environ.has_key('GLOBUS_LOCATION'):
    gl = os.environ['GLOBUS_LOCATION']
    INCDIRS = [os.sep.join([gl,dir]) for dir in INCDIRS]
    LIBDIRS = [os.sep.join([gl,dir]) for dir in LIBDIRS]

#------------------------------------------------------------------------------
# Usage
#------------------------------------------------------------------------------
def usage():
    print "Usage: %s [options]\n" % (os.path.basename(sys.argv[0]))
    print "-h, --help      Display this help and exit"
    print "    --confinc   Return the location of globus_config.h"
    print "    --inc       Return the location of globus header files"
    print "    --libdir    Return the location of the globus librairies"
    print "    --gsslib    Return the linker statement for linking with globus gss libraries"
    print "    --gsslibthr Return the linker statement for linking with globus gss libraries, threaded version"
    print "    --ftplib    Return the linker statement for linking with globus gridftp libraries"
    print "Report bugs to <castor-support@cern.ch>"

#------------------------------------------------------------------------------
# getConfinc
#------------------------------------------------------------------------------
def getConfinc():
    for directory in INCDIRS:
        if os.path.isfile(os.sep.join([directory, 'globus_config.h'])):
            return directory
    raise EnvironmentError('No globus install found')

#------------------------------------------------------------------------------
# getInc
#------------------------------------------------------------------------------
def getInc():
    for directory in INCDIRS:
        if os.path.isfile(os.sep.join([directory, 'globus_common.h'])):
            return directory
    raise EnvironmentError('No globus install found')

#------------------------------------------------------------------------------
# getLibstyle
#------------------------------------------------------------------------------
def getLibstyle():
    '''Return a pair with the directory where to find the globus libraries and
    a boolean saying whether the libraries have the flavour in their name'''
    for directory in LIBDIRS:
        if os.path.isfile(os.sep.join([directory, 'libglobus_common.so'])):
            return directory, False
        if os.path.isfile(os.sep.join([directory, 'libglobus_common_' + FLAVOUR + '.so'])):
            return directory, True
    raise EnvironmentError('No globus install found')

#------------------------------------------------------------------------------
# getLibdir
#------------------------------------------------------------------------------
def getLibdir():
    directory, isFlavourInLibName = getLibstyle()
    return directory

#------------------------------------------------------------------------------
# getGsslib
#------------------------------------------------------------------------------
def getGsslib(threaded):
    directory, isFlavourInLibName = getLibstyle()
    postfix = ''
    if isFlavourInLibName:
        postfix = '_' + FLAVOUR
        if threaded:
            postfix = postfix + 'pthr'
    value = '-L' + directory
    for lib in ['globus_gssapi_gsi', 'globus_gss_assist', 'globus_gsi_credential', 'globus_common']:
        value = value + ' -l' + lib + postfix
    return value

#------------------------------------------------------------------------------
# getFtplib
#------------------------------------------------------------------------------
def getFtplib():
    directory, isFlavourInLibName = getLibstyle()
    postfix = ''
    if isFlavourInLibName:
        postfix = '_' + FLAVOUR
    value = '-L' + directory
    for lib in ['globus_ftp_control', 'globus_gridftp_server', 'globus_common']:
        value = value + ' -l' + lib + postfix
    return value

#------------------------------------------------------------------------------
# Main Thread
#------------------------------------------------------------------------------

# Process command line arguments.
try:
    opts, args = getopt.getopt(sys.argv[1:], "h",
                               ["help", "confinc", "inc", "libdir",
                                "gsslib", "ftplib", "gsslibthr", "ftplibthr"])
except getopt.GetoptError:
    usage()
    sys.exit(2)

# Construct the return value based on the command line arguments.
try:
    for opt, arg in opts:
        if opt == "--help" or opt == "-h":
            usage()
        if opt == "--confinc":
            print getConfinc()
        if opt == "--inc":
            print getInc()
        if opt == "--libdir":
            print getLibdir()
        if opt == "--gsslib":
            print getGsslib(False)
        if opt == "--gsslibthr":
            print getGsslib(True)
        if opt == "--ftplib":
            print getFtplib()
except EnvironmentError, e:
    print >> sys.stderr, e
    sys.exit(1)
