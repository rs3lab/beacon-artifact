# Install dotnet
sudo apt-get update
sudo apt-get install -y dotnet-sdk-8.0

# Download Dafny, Linux kernel, and VM image

# pushd fuzzing-dir
# wget --no-check-certificate  https://zenodo.org/records/16366262/files/dafny.tar.gz?download=1 -O dafny.tar.gz
# tar -xzvf dafny.tar.gz
# 
# wget --no-check-certificate  https://zenodo.org/records/16366262/files/linux-kernel.tar.gz?download=1 -O linux-kernel.tar.gz
# tar -xzvf linux-kernel.tar.gz
# 
# wget --no-check-certificate https://zenodo.org/records/16366262/files/vm-image.tar.gz?download=1 -O vm-image.tar.gz
# tar -xzvf vm-image.tar.gz
# popd


# fatal error: sys/capability.h: No such file or directory 
sudo apt-get install -y libcap-dev
sudo apt-get install -y libelf-dev
sudo apt-get install -y libzstd-dev
sudo apt-get install -y qemu-system-x86

# install libbpf: https://github.com/libbpf/libbpf
git clone https://github.com/libbpf/libbpf
pushd libbpf
pushd src
make -j`nproc`
sudo make install
popd
popd

# Install go
mkdir go-env
pushd go-env
wget --no-check-certificate https://go.dev/dl/go1.19.linux-amd64.tar.gz
tar -xf go1.19.linux-amd64.tar.gz
GOROOT=`pwd`/go
GOPATH=`pwd`/gopath
mkdir $GOPATH
echo "export GOROOT=$GOROOT" >> ~/.bashrc
echo "export PATH=$GOROOT/bin:$PATH" >> ~/.bashrc
echo "export GOPATH=$GOPATH" >> ~/.bashrc
source ~/.bashrc
popd
