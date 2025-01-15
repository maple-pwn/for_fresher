
test:     file format elf32-i386


Disassembly of section .init:

00001000 <_init>:
    1000:	f3 0f 1e fb          	endbr32 
    1004:	53                   	push   %ebx
    1005:	83 ec 08             	sub    $0x8,%esp
    1008:	e8 93 00 00 00       	call   10a0 <__x86.get_pc_thunk.bx>
    100d:	81 c3 cb 2f 00 00    	add    $0x2fcb,%ebx
    1013:	8b 83 1c 00 00 00    	mov    0x1c(%ebx),%eax
    1019:	85 c0                	test   %eax,%eax
    101b:	74 02                	je     101f <_init+0x1f>
    101d:	ff d0                	call   *%eax
    101f:	83 c4 08             	add    $0x8,%esp
    1022:	5b                   	pop    %ebx
    1023:	c3                   	ret    

Disassembly of section .plt:

00001030 <__libc_start_main@plt-0x10>:
    1030:	ff b3 04 00 00 00    	push   0x4(%ebx)
    1036:	ff a3 08 00 00 00    	jmp    *0x8(%ebx)
    103c:	00 00                	add    %al,(%eax)
	...

00001040 <__libc_start_main@plt>:
    1040:	ff a3 0c 00 00 00    	jmp    *0xc(%ebx)
    1046:	68 00 00 00 00       	push   $0x0
    104b:	e9 e0 ff ff ff       	jmp    1030 <_init+0x30>

00001050 <puts@plt>:
    1050:	ff a3 10 00 00 00    	jmp    *0x10(%ebx)
    1056:	68 08 00 00 00       	push   $0x8
    105b:	e9 d0 ff ff ff       	jmp    1030 <_init+0x30>

Disassembly of section .plt.got:

00001060 <__cxa_finalize@plt>:
    1060:	ff a3 18 00 00 00    	jmp    *0x18(%ebx)
    1066:	66 90                	xchg   %ax,%ax

Disassembly of section .text:

00001070 <_start>:
    1070:	f3 0f 1e fb          	endbr32 
    1074:	31 ed                	xor    %ebp,%ebp
    1076:	5e                   	pop    %esi
    1077:	89 e1                	mov    %esp,%ecx
    1079:	83 e4 f0             	and    $0xfffffff0,%esp
    107c:	50                   	push   %eax
    107d:	54                   	push   %esp
    107e:	52                   	push   %edx
    107f:	e8 18 00 00 00       	call   109c <_start+0x2c>
    1084:	81 c3 54 2f 00 00    	add    $0x2f54,%ebx
    108a:	6a 00                	push   $0x0
    108c:	6a 00                	push   $0x0
    108e:	51                   	push   %ecx
    108f:	56                   	push   %esi
    1090:	ff b3 20 00 00 00    	push   0x20(%ebx)
    1096:	e8 a5 ff ff ff       	call   1040 <__libc_start_main@plt>
    109b:	f4                   	hlt    
    109c:	8b 1c 24             	mov    (%esp),%ebx
    109f:	c3                   	ret    

000010a0 <__x86.get_pc_thunk.bx>:
    10a0:	8b 1c 24             	mov    (%esp),%ebx
    10a3:	c3                   	ret    
    10a4:	66 90                	xchg   %ax,%ax
    10a6:	66 90                	xchg   %ax,%ax
    10a8:	66 90                	xchg   %ax,%ax
    10aa:	66 90                	xchg   %ax,%ax
    10ac:	66 90                	xchg   %ax,%ax
    10ae:	66 90                	xchg   %ax,%ax

000010b0 <deregister_tm_clones>:
    10b0:	e8 e4 00 00 00       	call   1199 <__x86.get_pc_thunk.dx>
    10b5:	81 c2 23 2f 00 00    	add    $0x2f23,%edx
    10bb:	8d 8a 30 00 00 00    	lea    0x30(%edx),%ecx
    10c1:	8d 82 30 00 00 00    	lea    0x30(%edx),%eax
    10c7:	39 c8                	cmp    %ecx,%eax
    10c9:	74 1d                	je     10e8 <deregister_tm_clones+0x38>
    10cb:	8b 82 14 00 00 00    	mov    0x14(%edx),%eax
    10d1:	85 c0                	test   %eax,%eax
    10d3:	74 13                	je     10e8 <deregister_tm_clones+0x38>
    10d5:	55                   	push   %ebp
    10d6:	89 e5                	mov    %esp,%ebp
    10d8:	83 ec 14             	sub    $0x14,%esp
    10db:	51                   	push   %ecx
    10dc:	ff d0                	call   *%eax
    10de:	83 c4 10             	add    $0x10,%esp
    10e1:	c9                   	leave  
    10e2:	c3                   	ret    
    10e3:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
    10e7:	90                   	nop
    10e8:	c3                   	ret    
    10e9:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi

000010f0 <register_tm_clones>:
    10f0:	e8 a4 00 00 00       	call   1199 <__x86.get_pc_thunk.dx>
    10f5:	81 c2 e3 2e 00 00    	add    $0x2ee3,%edx
    10fb:	55                   	push   %ebp
    10fc:	89 e5                	mov    %esp,%ebp
    10fe:	53                   	push   %ebx
    10ff:	8d 8a 30 00 00 00    	lea    0x30(%edx),%ecx
    1105:	8d 82 30 00 00 00    	lea    0x30(%edx),%eax
    110b:	83 ec 04             	sub    $0x4,%esp
    110e:	29 c8                	sub    %ecx,%eax
    1110:	89 c3                	mov    %eax,%ebx
    1112:	c1 e8 1f             	shr    $0x1f,%eax
    1115:	c1 fb 02             	sar    $0x2,%ebx
    1118:	01 d8                	add    %ebx,%eax
    111a:	d1 f8                	sar    %eax
    111c:	74 14                	je     1132 <register_tm_clones+0x42>
    111e:	8b 92 24 00 00 00    	mov    0x24(%edx),%edx
    1124:	85 d2                	test   %edx,%edx
    1126:	74 0a                	je     1132 <register_tm_clones+0x42>
    1128:	83 ec 08             	sub    $0x8,%esp
    112b:	50                   	push   %eax
    112c:	51                   	push   %ecx
    112d:	ff d2                	call   *%edx
    112f:	83 c4 10             	add    $0x10,%esp
    1132:	8b 5d fc             	mov    -0x4(%ebp),%ebx
    1135:	c9                   	leave  
    1136:	c3                   	ret    
    1137:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
    113e:	66 90                	xchg   %ax,%ax

00001140 <__do_global_dtors_aux>:
    1140:	f3 0f 1e fb          	endbr32 
    1144:	55                   	push   %ebp
    1145:	89 e5                	mov    %esp,%ebp
    1147:	53                   	push   %ebx
    1148:	e8 53 ff ff ff       	call   10a0 <__x86.get_pc_thunk.bx>
    114d:	81 c3 8b 2e 00 00    	add    $0x2e8b,%ebx
    1153:	83 ec 04             	sub    $0x4,%esp
    1156:	80 bb 30 00 00 00 00 	cmpb   $0x0,0x30(%ebx)
    115d:	75 27                	jne    1186 <__do_global_dtors_aux+0x46>
    115f:	8b 83 18 00 00 00    	mov    0x18(%ebx),%eax
    1165:	85 c0                	test   %eax,%eax
    1167:	74 11                	je     117a <__do_global_dtors_aux+0x3a>
    1169:	83 ec 0c             	sub    $0xc,%esp
    116c:	ff b3 2c 00 00 00    	push   0x2c(%ebx)
    1172:	e8 e9 fe ff ff       	call   1060 <__cxa_finalize@plt>
    1177:	83 c4 10             	add    $0x10,%esp
    117a:	e8 31 ff ff ff       	call   10b0 <deregister_tm_clones>
    117f:	c6 83 30 00 00 00 01 	movb   $0x1,0x30(%ebx)
    1186:	8b 5d fc             	mov    -0x4(%ebp),%ebx
    1189:	c9                   	leave  
    118a:	c3                   	ret    
    118b:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
    118f:	90                   	nop

00001190 <frame_dummy>:
    1190:	f3 0f 1e fb          	endbr32 
    1194:	e9 57 ff ff ff       	jmp    10f0 <register_tm_clones>

00001199 <__x86.get_pc_thunk.dx>:
    1199:	8b 14 24             	mov    (%esp),%edx
    119c:	c3                   	ret    

0000119d <print_banner>:
    119d:	55                   	push   %ebp
    119e:	89 e5                	mov    %esp,%ebp
    11a0:	53                   	push   %ebx
    11a1:	83 ec 04             	sub    $0x4,%esp
    11a4:	e8 3b 00 00 00       	call   11e4 <__x86.get_pc_thunk.ax>
    11a9:	05 2f 2e 00 00       	add    $0x2e2f,%eax
    11ae:	83 ec 0c             	sub    $0xc,%esp
    11b1:	8d 90 30 e0 ff ff    	lea    -0x1fd0(%eax),%edx
    11b7:	52                   	push   %edx
    11b8:	89 c3                	mov    %eax,%ebx
    11ba:	e8 91 fe ff ff       	call   1050 <puts@plt>
    11bf:	83 c4 10             	add    $0x10,%esp
    11c2:	90                   	nop
    11c3:	8b 5d fc             	mov    -0x4(%ebp),%ebx
    11c6:	c9                   	leave  
    11c7:	c3                   	ret    

000011c8 <main>:
    11c8:	55                   	push   %ebp
    11c9:	89 e5                	mov    %esp,%ebp
    11cb:	83 e4 f0             	and    $0xfffffff0,%esp
    11ce:	e8 11 00 00 00       	call   11e4 <__x86.get_pc_thunk.ax>
    11d3:	05 05 2e 00 00       	add    $0x2e05,%eax
    11d8:	e8 c0 ff ff ff       	call   119d <print_banner>
    11dd:	b8 00 00 00 00       	mov    $0x0,%eax
    11e2:	c9                   	leave  
    11e3:	c3                   	ret    

000011e4 <__x86.get_pc_thunk.ax>:
    11e4:	8b 04 24             	mov    (%esp),%eax
    11e7:	c3                   	ret    

Disassembly of section .fini:

000011e8 <_fini>:
    11e8:	f3 0f 1e fb          	endbr32 
    11ec:	53                   	push   %ebx
    11ed:	83 ec 08             	sub    $0x8,%esp
    11f0:	e8 ab fe ff ff       	call   10a0 <__x86.get_pc_thunk.bx>
    11f5:	81 c3 e3 2d 00 00    	add    $0x2de3,%ebx
    11fb:	83 c4 08             	add    $0x8,%esp
    11fe:	5b                   	pop    %ebx
    11ff:	c3                   	ret    
