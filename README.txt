This tool may seem useless at first glance, until you realize
that OleView, AxMan, ComRaider, and virtually every other tool
out there enumerate (and retrieve) TLB for ONLY REGISTERED COM/ACTIVEX
objects. What if you have just the file and need the tlb? This pulls the 
TLB out for you. From there you can use OleView.exe to view the TLB
or save it as a human readable IDL.

1. Run the MS OLEViewer app (Start>>Run>>oleview.exe). 
2. From there, use File>>View Typelib. 
3. In the type library view, just use File>>Save As to save it
as IDL.



Z:\>who_has_tlb.exe

----------------------------------------------------------
Who Has TLBs?

Finds and extracts TypeLib information embedded in PEs.

                                    Matasano Security LLC.
                                      stephen@matasano.com
                                              January 2009
----------------------------------------------------------

Usage: who_has_tlb.exe [options]

Options:
  -h, --help            show this help message and exit
  -f FNAME, --file=FNAME
                        Name of file to check for embedded TypeLib
                        information.
  -d DIRNAME, --dir=DIRNAME
                        Name of directory to check recursively for embedded
                        TypeLib information.
  -e, --extract         Extract Typelib information if it is found.

Z:\>
