
import procedure (last updated on November 15, 2016):

git clone https://github.com/sctplab/usrsctp.git usrsctp-git
cd usrsctp-git/usrsctplib
rm Makefile.* CMakeLists.txt
cd ../..
cp -R usrsctp-git/usrsctplib usrsctp
rm -rf usrsctp-git
