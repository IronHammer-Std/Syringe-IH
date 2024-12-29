
```
SyringeIH是在公版Syringe0.7.2.0的基础上升级而来的。
提供了包括扩展INJ格式，钩子优先级，相对钩子，更加人性的IE报错说明等功能。
                                                  ——钢铁之锤 2024年9月


DLL可以放在游戏目录，或放在Patches子目录。

扩展INJ格式：

原来的格式：
<十六进制地址> = <函数名>, <覆写长度>
新的格式：
<十六进制地址> = <函数名>, <覆写长度>[, <优先级>][, <次优先级>]
后两个为可选项。如果填写了次优先级，则必须先填写优先级。
优先级判断规则：
	1、比较优先级，值大的先执行
	2、若优先级相等，比较次优先级，
		（1）sub_priority非空的比sub_priority为空串的先执行
		（2）两个都非空时，比较字典序，字典序大的先执行（通过strcmp确定字典序）

Syringe.json中的配置：

一些默认值：
  "DefaultExecutableName": "gamemd.exe", //启动的程序，默认留空
  "DefaultCommandLine": "-cd -speedcontrol -log", //启动参数，默认留空
	注：如果通过bat启动Syringe，那么命令行当中的参数会覆盖上述两个参数

  "InfiniteWaitForDebug": false,//决定是否在发生异常时额外弹窗以等待调试，用于调试某些Bug，默认false
  "LongStackDump": false,//是否会延长栈转储以获得完整栈信息，默认false
  "OnlyShowStackFrame": false,//是否在栈转储中仅显示函数调用层级，默认false
  "ExceptionReportAlwaysFull": true,//是否总是显示每次异常的全部信息，默认false（即除了第一次出现异常，后面都只有简略信息）


  "IsRunningYR": true, //决定是否启用Syringe的运行前信息 默认false
  "RemoteDatabaseDump": false, //运行前信息启用时，是否转储一份到RemoteData.dmp 默认false
  "DetachAfterInjection": false, //是否在注入完成后与gamemd分离， 默认false（可以加上自己的调试器）
  "EnableHandshakeCheck": true,//是否进行握手检查（如Ares对gamemd的检查），默认true
	注：！！如果使用steam版红警，务必设置为false

  HookAnalysis :钩子分析器设置
  填true或false是完全打开或完全关闭，默认false。
  也可分开设置：HookAnalysis": {
    "ByLibrary": <bool，是否按照库分析>,
    "ByAddress": <bool，是否按照地址分析>,
    "LibraryRange": [ <字符串数组，列出全部需要分析的库，留空为所有库> ],//例如：[ "Ares.dll" , "Phobos.dll" ]
    "AddressRange": [ <数组，其中对象的格式为["开始地址","结束地址"]，列出所有需要分析的范围，留空为所有地址> ]//例如[[ "400000", "4FFFFF" ],[ "700000", "7FFFFF" ]]
  }
  完整的示例如下：
  "HookAnalysis": {
    "ByLibrary": false,
    "ByAddress": true,
    "LibraryRange": [ "Ares.dll" ],
    "AddressRange": [ [ "400000", "7FFFFF" ] ]
  }

  DisableHooks：禁用钩子，全局设置，可以覆盖dll对应的json里面的设置
   "DisableHooks": [
    "DLL名称": [ <字符串数组，列出全部钩子名> ],
  ]
  完整的示例如下：
  "DisableHooks": [
    "Ares.dll": [ "dfdfds", "fdfdsfds", "dddd" ],
  ]

  EnableHooks：启用钩子，优先级高于所有的禁用，用法同DisableHooks

一份Syringe.json的示例：
{
  "HookAnalysis": false,
  "DefaultExecutableName": "gamemd.exe", 
  "DefaultCommandLine": "-cd -speedcontrol -log", 
  "IsRunningYR": true, 
  "RemoteDatabaseDump": false, 

  "DisableHooks": [],
  "EnableHooks": []
}



配置配套的JSON：
同INJ文件的使用，如Ares.dll配套的JSON名为Ares.dll.json

MemoryCopyRange：
内存区域复制+相对地址修正
格式："MemoryCopyRange": [
    [<数组，其中的元素："起始地址","结束地址","注册名","地址1","地址2",……>]//例如：[ "5B43F0", "5B4400", "AlwaysTrue" ]
  ]
其中的地址1，地址2为需要修改指针位置的地址，例如要复制的是函数时，把其中每一个call指令都录进去（录入的是指针的地址，也就是call指令的地址+1）

RelativeHooks：
相对钩子，用于钩插件的dll。(要附着的DLL可以填gamemd.exe，但此时应换算出相对地址)
格式："RelativeHooks": [
    [<数组，其中的元素："要附着的DLL","相对地址","函数名","覆写长度","优先级"（可选）,"副优先级"（可选）,……>]
		//例如：["Ares.dll","EC","Test","5","100000","SubPriorityExample"] 将插入到Ares.dll+0xEC的位置
  ]

DisableHooks同Syringe.json
EnableHooks在单独配套的JSON中不可用

一份DLL配套的Json的示例：
{
  "MemoryCopyRange": [
    [ "5B43F0", "5B4400", "Function_AlwaysTrue" ],
  ],

  "RelativeHooks": [
    ["Ares.dll","EC","Test","5","100000","SubPriorityExample"]
  ]

  "DisableHooks": [
    "Ares.dll": [ "dfdfds", "fdfdsfds", "dddd" ],
  ]
}
```

