gcc -fno-stack-protector -no-pie -Og  -m32 target.c -o target

checksec --file=./target

objdump -d ./target > ref.txt

gcc exploit.c -o exploit 

./exploit | ./target 