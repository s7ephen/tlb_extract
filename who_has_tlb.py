#!/usr/bin/env python 
"""
----------------------------------------------------------
Who Has TLBs?
    
Finds and extracts TypeLib information embedded in PEs.

                                    Matasano Security LLC. 
                                      stephen@matasano.com 
                                              January 2009
----------------------------------------------------------
"""

import os
import os.path
import sys
import code
import optparse

global RIPTLBS #Automatically extract the TLB?
global TLB2IDL #Automatically convert the TLB to IDL?
RIPTLBS = False
TLB2IDL = False

try:
    import pythoncom
except ImportError:
    print "Unable to import PythonCOM module, quitting!\n"
    sys.exit(1) 
try:
    import ctypes
except ImportError:
    print "Unable to import the CTYPES module, quitting!\n"
#    sys.exit(1) 
try:
    import pefile
except ImportError:
    print "Unable to import PythonCOM module, quitting!\n"
    sys.exit(1) 
    
def _checkfile(file):
    """
        Check if a file has TLB using LoadTypeLib
    """
    try:
        tlb = pythoncom.LoadTypeLib(os.path.abspath(file))
    except:
        pass
    else:
        print "\n!!! FOUND embedded TypeLib info in: ", file, " !!! "
        #print "!!! TLB INFO FOUND IN %s !!!" % os.path.abspath(file)
        tlbattr = tlb.GetLibAttr()
#        print "\t",repr(tlbattr),"\n"
#        mycmd = code.InteractiveConsole(locals()); mycmd.interact()
        if RIPTLBS == True:
#            if os.path.splitext(file)[1] in (".exe", ".dll", ".ocx"):
#                riptlb(os.path.abspath(file))
#            else:
#                print "\tNot a PE, skipping..."
            riptlb(os.path.abspath(file))

def riptlb(file):
    """
        traverse the PE to find the Typelib blob.

        THANKS FOR THE PEFILE HELP LAWLER!
    """
    try: 
        pe = pefile.PE(file, fast_load=True)
        rsrc_va = 0
        offset_type = 0
        offset_name = 0
        offset_language = 0
        for section in pe.sections:
            if ".rsrc" in section.Name:
                #print "Found Resource Section"
                #print section.Name,".", hex(section.VirtualAddress)
                rsrc_va = section.VirtualAddress
        pe.parse_data_directories( directories=[ 
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']
            ] ) 
    except pefile.PEFormatError:
        print "\tNot a PE....skipping"
        return 0

    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if entry.name is None:
            pass
        elif entry.name.string == u'TYPELIB':
#            print ("Found Typelib entry in Resource Section")
            offset_type = entry.struct.OffsetToDirectory
            offset_name = pe.parse_resources_directory((rsrc_va+offset_type)).entries[0].struct.OffsetToDirectory 
            offset_language = pe.parse_resources_directory(rsrc_va+offset_name).entries[0].struct.OffsetToDirectory
            resource_data = pe.parse_resource_data_entry(rsrc_va+offset_language)
#            mycmd = code.InteractiveConsole(locals()); mycmd.interact()
            blob = pe.get_data(resource_data.OffsetToData, resource_data.Size)
            tlbfname = os.path.splitext(file)[0]+os.path.splitext(file)[1].replace(".","_")+".tlb"
            tlbf_h = open(tlbfname, 'wb')
            tlbf_h.write(blob)
            tlbf_h.close()
            print "\tExtracted TLB to: %s" % tlbfname
#            print repr(blob)[:30]
    
    del(pe)
  
def check_a_dir(adir):
    directories = [adir]
    while len(directories)>0:
        directory = directories.pop()
        for name in os.listdir(directory):
            fullpath = os.path.join(directory,name)
            if os.path.isfile(fullpath):
                #print "Checking", fullpath,'.'
                _checkfile(fullpath)
            elif os.path.isdir(fullpath):
                directories.append(fullpath)  # It's a directory, store it.

def _checkdir(adir):
    print "Recursing into directory %s" % os.path.abspath(adir)
    for root, dirs, files in os.walk(adir, topdown=False):
        for file in files:
            #print "Checking %s for TLB info." % os.path.abspath(file)
            _checkfile(file)
        for a in dirs:
            _checkdir(os.path.abspath(a))

if __name__ == "__main__":
    parser = optparse.OptionParser()
    parser.add_option(
        '-f','--file',
        action="store", type='string', dest="fname",
        help="Name of file to check for embedded TypeLib information.")
    parser.add_option(
        '-d','--dir',
        action="store", type='string', dest="dirname",
        help="Name of directory to check recursively for embedded TypeLib information.")
    parser.add_option(
        '-e','--extract',
        action="store_true", dest="RIPTLBS", default=False,
        help='Extract Typelib information if it is found.')
#    parser.add_option(
#        '-c','--convert',
#        action="store_true", dest="TLB2IDL", default=False,
#        help='Automatically convert the extracted TLB to IDL.')
    if len(sys.argv) == 1:
        print __doc__
        sys.argv.append("--help")
    options, args = parser.parse_args()    

    RIPTLBS = options.RIPTLBS
#    TLB2IDL = options.TLB2IDL

    pythoncom.CoInitialize()         
    if options.fname and options.dirname:
        print "Please specify a filename OR a directory, not both."
        sys.exit(1)
    elif options.fname:
        checkfile = options.fname
        if not os.path.exists(checkfile):
            print "File %s does not exist. Quitting" % checkfile
            sys.exit(1)
    elif options.dirname:
        checkdir = options.dirname
        if not os.path.exists(checkdir):
            print "Directory %s does not exist. Quitting" % checkdir
            sys.exit(1)

    if options.fname:
        _checkfile(checkfile)
    else:
#   OS.PATH sucks...not using it anymore.
#        os.chdir(checkdir)
#        _checkdir(checkdir)
        check_a_dir(checkdir)
    pythoncom.CoUninitialize()
