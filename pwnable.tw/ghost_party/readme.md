# PWN in C++ basic by ANGELBOY

https://www.slideshare.net/AngelBoy1/pwning-in-c-basic

This article was written in chinese , so i barely understand but by debugging and thank to visualizable photos that Angelboy provided , i was able to figure it out.

# Review code and analyze the vulnerbility

```C++
class Ghost {
	public :
		Ghost():name(NULL),age(0){
			type = "Ghost";
		};

		Ghost(const Ghost &copyghost){
			name = new char[strlen(copyghost.name) + 1] ;
			strcpy(name,copyghost.name) ;
			type = copyghost.type;
			age = copyghost.age ;
			msg = copyghost.msg ;
		}

		Ghost& operator=(const Ghost &copyghost){
			name = new char[strlen(copyghost.name) + 1] ;
			strcpy(name,copyghost.name) ;
			type = copyghost.type;
			age = copyghost.age ;
			msg = copyghost.msg ;
		}
		
		char *getname(){
			return name ;
		}

		string gettype(){
			return type ;
		}


		virtual void speak(){
			cout << "<<" <<  name << ">>" <<" speak : " << msg << endl;
		};
		virtual int changemsg(string str){
			msg = str ;
			return 1 ;
		}

		virtual void ghostinfo(){
			cout << "Type : " << type << endl ;
			cout << "Name : " << name << endl ;
			cout << "Age : " << age << endl ;	

		}

		virtual ~Ghost(){
			age = 0 ;
			msg.clear();
			type.clear();
			memset(name,0,malloc_usable_size(name));
			delete[] name ;
		};

	protected :
		int age ;
		char *name ;
		string type ;
		string msg ;

};

class Vampire : public Ghost {
	public :
		Vampire():blood(NULL){
			type = "Vampire" ;
		};
		
		Vampire(int ghostage,string ghostname,string ghostmsg){
			type = "Vampire";
			age = ghostage ;
			name = new char[ghostname.length() + 1];
			strcpy(name,ghostname.c_str());
			msg = ghostmsg ;
			blood = NULL ;
		};

		void addblood(string com){
			blood = new char[com.length()+1];
			memcpy(blood,com.c_str(),com.length());
		}


		void ghostinfo(){
			cout << "Type : " << type << endl ;
			cout << "Name : " << name << endl ;
			cout << "Age : " << age << endl ;	
			cout << "Blood : " << blood << endl ;
		}
		~Vampire(){
			delete[] blood;
		};
	private :
		char *blood ;
};

class Devil : public Ghost{
	public :
		Devil():power(NULL){
			type = "Devil" ;
		};

		Devil(int ghostage,string ghostname,string ghostmsg){
			type = "Devil";
			age = ghostage ;
			name = new char[ghostname.length() + 1];
			strcpy(name,ghostname.c_str());
			msg = ghostmsg ;
			power = NULL ;
		};

		Devil(const Devil &copyghost){
			name = new char[strlen(copyghost.name) + 1] ;
			strcpy(name,copyghost.name) ;
			type = copyghost.type;
			age = copyghost.age ;
			msg = copyghost.msg ;
			power = new char[strlen(copyghost.power)+1];
			strcpy(power,copyghost.power);

		};

		void addpower(string str){
			stringstream ss ;
			power = new char[str.length()+1];
			memcpy(power,str.c_str(),str.length());
			cout << "Your power : " << power << endl ;
		};

		void ghostinfo(){
			cout << "Type : " << type << endl ;
			cout << "Name : " << name << endl ;
			cout << "Age : " << age << endl ;	
			cout << "power : " << power << endl ;
		}

		~Devil(){
			delete[] power;
		};
	private :
		char *power ;
};
```

The source code have many `subclass` that inherit from super class `Ghost` but i will just focus diffrence between `Vampire` and `Devil` . But before that let take a look at the slide of Angelboy.

![image](https://github.com/DoQuangPhu/CTF_writeups/assets/93699926/75604af7-699a-4b79-972c-4ed737fa3a14)

In OOP programming every object will has it's own virtual function table . this table is the address of exe which have `read` permisson only. And we can find this address of it at the very begining of every object.

![image](https://github.com/DoQuangPhu/CTF_writeups/assets/93699926/82e16ee2-10fe-48e0-8b25-186974337bb2)

this is how `Ghost` look like when we create it.  `0x0000555555610b60` is the binary address aka `vftable`,`0x0000000000000064`-age,`0x00005555556280a0`-name,`0x0000555555628058`-type,`0x0000555555628078`-message,and last one `0x00005555556280c0`is power beause the object i created is `Devil`

And you have already known that our object is located on the heap , so if by some way if we can over write the `vftable` with a address of our fake vftable then we can PWN a shell.

TBH the part of `Vector` , i have not understand it thoroughly so i wont try to explain it . Sorry!

So let moving on to the next part.

![image](https://github.com/DoQuangPhu/CTF_writeups/assets/93699926/b0d9036f-b2ed-4216-90d1-b32a43742c3c)

as if you have not know that , in OOP objects have contructor and destructor function and they work exactly like their name . 
And in the code above we can spot a vulnerbility here or an error in this case cause it make the program crash . Thing we talking about here is that `Stu` is lack of `Copy CONSTRUCTOR`
In this case `Stu.id` can work perfectly fine cause it a prime data type . but `Stu.name` is in contrast is a pointer . so if you copy the data this way the object getting `push_back` into 
`Vector` stulist will have the same address of the Object student.name - a address located on heap. and when we hit the the return point `destructor` funtion will be call automatically , the object get copy in stulist and object student .
and because this two object.name is the same address so we got a double free. This type of copy is called as shallow copy and we should have counter this problem by `deep_copy` - make a propper copy constructor.
if you still confuse between shallow copy and deep copy then i reccommend this video : https://youtu.be/tbtFKuTcZKs
it just one of a tons of video about this problem . you can watch the others video as you like.

Now look at `Devil` and `Vampire` we can clearly see that `Vampire` is lack of copy contructor. Now let analyze another function `smallist` which called when ever we create a `Ghost` :

```C
int smalllist(T ghost){
	unsigned int choice ;
	cout << "1.Join       " << endl;
	cout << "2.Give up" << endl ;
	cout << "3.Join and hear what the ghost say" << endl ;
	cout << "Your choice : " ;
	cin >> choice ;
	if(!cin.good()){
		cout << "Format error !" << endl ;
		exit(0);
	}

	switch(choice){
		case 1 :
			ghostlist.push_back(ghost);
			cout << "\033[32mThe ghost is joining the party\033[0m" << endl ;
			return 1 ;
			break ;
		case 2 :
			cout << "\033[31mThe ghost is not joining the party\033[0m" << endl ;
			delete ghost ;
			return 0 ;
			break ;
		case 3 :
			ghostlist.push_back(ghost);
			speaking(*ghost);
			cout << "\033[32mThe ghost is joining the party\033[0m" << endl ;
			return 1;
			break ;
		default :
			cout << "\033[31mInvaild choice\033[0m" << endl ;
			delete ghost ;
			return 0 ;
			break ;

	}
}
```

Take a look at `case 3` it do perfectly indentical with the vulnerable piece of code in the slide when object `ghost` after getting push)back in to the Vector `ghostlist`.
and then ghost get called again by speak, after that when hit return point `ghost` will call it destructor . It maybe some mistake here , im not sure if ghost.destructor will be called here or when we reach the return point in addghost becuase ghost was created in addGhost funtion. you can debug it your self.

And after the ghost.destructor get called we should have a chunk in the bin list that chunk is  ghost.blood if you create a object of Vampire.But still we have that pointer in the ghostlist[indexOfThatObject].blood , we can create a double free here. using that you can proceed on an exploit and PWN a shell.

This is more like a note i take for my self so i know it still lack of many knowledges . Sorry for that!
