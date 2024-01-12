# ta中需要被编译的源代码定义
# 在 Makefile 中，sub.mk 文件通常被包含进来以提供额外的编译规则和变量定义。
# 它可以用于定义特定模块或组件的编译规则，同时也可以用于指定特定模块所需的头文件搜索路径、源文件列表等。
global-incdirs-y += include
srcs-y += paillier_ta.c

# To remove a certain compiler flag, add a line like this
#cflags-template_ta.c-y += -Wno-strict-prototypes
