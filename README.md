自己收集与编写的常用IDA脚本，通常用于反混淆

公开的只支持arm64的指令集

# flare_fast_br.py

使用flare轻量级的模拟执行插件，用于对抗函数开头br register 的花指令混淆。

# flare_fast_string.py

使用flare轻量级的模拟执行插件，记录执行过程中对于data段的修改，用于对抗将字符串解密放到函数开头的混淆。

# unicorn_fast_string.py / unicorn_fast_br.py

对于大型（超过50M）的二进制，比如ios的应用，emu_fast_string中使用的插件效率慢到没法用。

这个组件使用unicorn主动加载，能快的多，但是要自己定制很多功能。

# ios_calling_convention_FIX

demo

尝试修复IOS逆向中的非标准调用约定的短函数，例如下面这样的汇编
```
__text:00000001011B4180 ; void __usercall objc_release_X23_1172(id X23@<X23>)
__text:00000001011B4180                 MOV             X0, X23 ; id
__text:00000001011B4184                 B               _objc_release
__text:00000001011B4184 ; End of function objc_release_X23_1172

__text:00000001011B4188 ; void __usercall objc_release_X19_1362(id X19@<X19>)
__text:00000001011B4188                 MOV             X0, X19 ; id
__text:00000001011B418C                 B               _objc_release
__text:00000001011B418C ; End of function objc_release_X19_1362

__text:00000001011B4190 ; void __usercall objc_release_X24_912(id X24@<X24>)
__text:00000001011B4190                 MOV             X0, X24 ; id
__text:00000001011B4194                 B               _objc_release
__text:00000001011B4194 ; End of function objc_release_X24_912
```


