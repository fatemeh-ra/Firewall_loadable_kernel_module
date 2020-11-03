## Firewall loadable kernel module
This repo contains implementation of linux Firewall loadable kernel module written in C.
It uses a character device driver to transfer configuration data from user space to kernel mode.

This firewall works in 2 different modes:

1. **White List mode** : In this mode all the IP:Ports are filtered in the first stage of the kernel, unless the destination or sender of the packet is in the whitelist.
2. **Black List mode** : By using the kernel module in this mode, we should specify all the unwanted IP:Ports to be filtered, other packets will pass the firewall.

The configuration of the kernel module stored in ``Config.txt`` that can be edited in user mode. This configuration consists of the kernel module mode and the list of IP:Ports related to that mode.

A ``MakeFile`` is required to build the kernel module, the paths of libraries used to build this kernel module specified in this MakeFile.

### Running

* **step1**: in the first step the kernel module must be built by running the command ``make``.
* **step2**: then the kernel module must be initiated with the command ``sudo insmod packet.ko``. you can check the correctness of this step by this command ``lsmod``, in the output of this command you should see the name of the kernel module "packet".
* **step3**: you can see the log created by the kernel module in kernel log file by running ``tail -f \var\log\kern.log``
* **step4**: finally for removing the kernel module from the running kernel you can use the command ``sudo rmmod packet.ko``.



