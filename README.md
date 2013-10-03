Namateon
========

Namateon Application Switch

# compile source files
make

# make config in json
vim configuration

#install & start
sudo insmod namateonmod.ko
sudo sh -c "cat configuration > /proc/namateon/conf"
sudo sh -c "echo 1 > /proc/namateon/start"

#stop & remove
sudo sh -c "echo 0 > /proc/namateon/start"
sudo rmmod namateonmod.ko
