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