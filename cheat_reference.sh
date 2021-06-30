#!/bin/bash

echo "Reference lookup for 58 programming languages"

echo "Languages Supported: arduino/ assembly/ awk/ bash/ basic/ bf/ c/ chapel/"
echo "clean/ clojure/ coffee/ cpp/ csharp/ d/ dart/ delphi/ dylan/ eiffel/ elixer"
echo "elisp/ elm/ erlang/ factor/ fortran/ forth/ fsharp/ go/ groovy/ haskell/ java/ js/ "
echo "julia/ kotlin/ latex/ lisp/ lua/ matlab/ nim/ ocaml/ octave/ perl/ perl6 php/ pike/"
echo "python/ python3/ r/ racket/ ruby/ rust/ scala/ scheme/ solidity/ swift/ tcsh/ tcl/ objective-c/ vb/ vbnet/ "
echo "Other Topics cmake/ django/ flask/ git/ "

echo "Select language: "
read varlang
echo "Question use + (plus) for multiple words (eg. creating+array)"
read varquestion

curl  cht.sh/$varlang/$varquestion
