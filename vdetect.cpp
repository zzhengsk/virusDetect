#include <cstdlib>
#include <fstream>
#include <iostream>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <vector>
#include <sstream>
using namespace std;

#define HEX_RANGE(ch) ((ch!=' ')&&((ch>='0'&& ch<='9')||(ch>='a'&& ch<='f')||(ch='A'&& ch<='G')))

void usageWrongMsg(char *processname);
void openFailMsg(const char* filename);
void recordSequence(const char* filename);
string transInputstr(string str);
int checkSequence(string str, unsigned long int begin_byte, char* filename);

// to store the information of malicious sequence and name
class MalList
{
    public:
        bool checkMalNum(int malNum);
        void updateSize();
        unsigned int getSize();
        void addName(string name);
        void addSequence(string seq);
        string getName(int malNum);
        string getSequence(int malNum);
        int token(int num);
        
    private: 
        unsigned int listSize;
        vector<string> malName;
        vector<string> malSeq;        
} mList;

bool q_flag = false, s_flag = false, d_flag = false;    // for options
bool mal_flag = false;  // if there has any malformed line in .str file, true
bool found = false;     // once found any sequence, it won't be false any more

int main (int argc,char *argv[])
{
    int tmp;
    string filename;
    int exitstatus = 0;

    while((tmp=getopt(argc,argv,"qsd:"))!=EOF){
        switch(tmp){
            case 'q':
                q_flag = true;  break;
            case 's':
                s_flag = true;  break;
            case 'd':       
                d_flag = true;
                filename = optarg;   // .str file name is given by user
                break;
            // invalid input will get the information and exit;
            default:
                usageWrongMsg(argv[0]);
                exit(-1);
        }
    }
         // default file
    if(d_flag != true)  filename.assign("vdetect.str");
    
    recordSequence(filename.c_str());       
    if(mList.getSize()<=0){
        cerr<<"nothing in "<<filename<<" to compare"<<endl; exit(-1);
    }

    // adjust the arguments 
    argc -= optind;     argv += optind;  
      
    if(argc < 1)        // check if there has any file to scan  
    {                   //no files, check stander input
        string instr, transstr;
        char inname[6] = "input";
        char *inputname = inname; 
        if(!q_flag)
            cout<<endl<<"input a string for scan(double enter to quit): "<<endl;
        unsigned long int begin_byte = 1;
        while(getline(cin,instr))
        {   
            if(instr.empty()){
               break;		// no more input 
            }        

            // check the input string, if contain \xnn, translate
            transstr = transInputstr(instr);
            
            // scan the input string
            checkSequence(transstr, begin_byte, inputname);
            if(found && s_flag)
                break;
            begin_byte = begin_byte + transstr.size()+1;
        }
    }
    
    else        // check the files
    {
        ifstream ifs;
        string line, transstr;
        bool match = false;
        char ch;
        unsigned long int begin_byte;
        for(int i=0; i<argc; i++){
            ifs.open(argv[i]);
            if(ifs.fail()){
                openFailMsg(argv[i]);
                ifs.close();
                continue;
            }                   
            // read char by char until one whole line, then reconstruct/translate
            // the string, then scan          
            
            // begin at byte
            begin_byte = 1;                                           
            while(!ifs.eof()){                
                line.clear();   transstr.clear();                
                ifs.get(ch);               
                while(ch != '\n' && !ifs.eof()){
                    line += ch;
                    ifs.get(ch);
                }
                
                if(line.empty()){
                    begin_byte++;   continue;                
                }   // empty line
                else    transstr = transInputstr(line);
                
                match = checkSequence(transstr, begin_byte, argv[i]);
                if(match<0){
                    cerr<<"internal consistencies"<<endl;
                    ifs.close();
                    continue;   // current file has problem, go to the next file 
                }
                          
                // if found any and -s set, stop scanning, check next file
                if(found && s_flag)
                    break;          
                                
                // adjust the byte position  
                begin_byte = begin_byte + transstr.size()+1;   
            }       
            ifs.close();    // end of scan one file
        }   
    }   // end of scan files
       
    // check exit status 
    // finish all of the search and -s not set
    if(found){
        if(mal_flag)
            exitstatus = 3;
        else   
            exitstatus = 1;
    }    
    
    else{
        if(mal_flag)   
            exitstatus = 2;
        else 
            exitstatus = 0;
    }

    return exitstatus;
}

void usageWrongMsg(char *processname){
    cerr<<"invalid input, please check the following format"<<endl;
    cerr<<"Usage: "<<processname<<" [-q] [-s] [-d strfile] [file1 [...]]"<<endl;
}

void openFailMsg(const char *filename){
    errno = 3;
    perror("perror");
    cerr<<"can't open the file "<<filename<<endl;
}

void recordSequence(const char* filename){
    ifstream ifs; 
    ifs.open(filename);
    if(ifs.fail()){
        openFailMsg(filename);
        ifs.close();
        exit(0);
    }
    // now the file is open
    int lineNum = 1, hexNum = 0;
    string name,sequence, temp, num; 
    char ch;
    bool hex_flag = false;  // for \xnn
    
    while(!ifs.eof())
    {
        ifs.get(ch);
        name.clear();   sequence.clear();
        
        // empty line
        if(ch == '\n')
            continue;
	// skip leading space
	if(ch == ' ')
	    continue;	
        // skip the comment line      
        if(ch == '#'){
            while(ch != '\n')
                ifs.get(ch);
            lineNum++;
            continue;
        }
        
        // if start with ':', no name, malformed line;
        if(ch == ':'){
            while(ch != '\n'){   
                name += ch;
                ifs.get(ch);
            }
            if(!q_flag)
                cout<<"line "<<lineNum++<<": Malformed line in "<<filename<<endl;
            mal_flag = true;    continue;
        }
        
        // get the name
        while(ch != ':' && ch != '\n'){   
            name += ch;
            ifs.get(ch);
        }
        // no ';', malformed line
        if(ch == '\n'){          
            if(!q_flag)
                cout<<"line "<<lineNum++<<": Malformed line in "<<filename<<endl;
            mal_flag = true;    continue;
        }
        
        // skip the ':'
        ifs.get(ch);
        // skip leading space of the sequence
        if(ch == ' ')
            while (ch == ' ')
                ifs.get(ch);
        
        while(ch != '\n' && !ifs.eof()){
            temp.clear();   num.clear();
            hex_flag = false;
            temp += ch;
            // check the format \xnn
            if(ch == '\\'){       
                if(ifs.get(ch) && !ifs.eof())
                    temp += ch;
                if(ch == 'x'){      
                    if(ifs.get(ch) && !ifs.eof())
                        temp += ch;
                    if(HEX_RANGE(ch)){
                        num += ch;
                        if(ifs.get(ch) && !ifs.eof())
                            temp += ch;
                        if(HEX_RANGE(ch)){
                            hex_flag = true;
                            num += ch;
                            stringstream ss;
                            ss<<hex<<num;
                            ss>>hexNum;
                            ch = hexNum;
                        }
                    }
                }             
            }                   
            if(hex_flag)
                sequence += ch;
            else
                sequence += temp;
            ifs.get(ch);
        }
        
        if(sequence.empty()){
            // no sequence, malformed line
            if(!q_flag)
                cout<<"line "<<lineNum++<<": Malformed line in "<<filename<<endl;
            mal_flag = true;    continue;
        }
        
        mList.addName(name);
        mList.addSequence(sequence);
        mList.updateSize();        
        lineNum++;
    }
    ifs.close();
}

string transInputstr(string str){
    string result, temp, num;
    result.clear(); temp.clear(); num.clear();
    char ch = ' ';    // store \xnn
    int hexNum=0;
    bool hex_num = false;
    
    // check for \xnn
    for(int i=0; i<str.size(); ){
        temp += str[i];
        if(str[i++] == '\\'){
            if(i<str.size()){
                if(str[i] == 'x'){
                    temp += str[i++];       
                    if(i<str.size()){
                        temp += str[i];    
                        if(HEX_RANGE(str[i])){
                            num += str[i];     
                            i++;               
                            if(i<str.size()){
                                temp += str[i];     
                                if(HEX_RANGE(str[i])){
                                    hex_num = true; 
                                    num += str[i];      
                                    stringstream ss;
                                    ss<<hex<<num;
                                    ss>>hexNum;
                                    ch = hexNum;
                                }
                                i++;                             
                            }
                        }
                        else    i++;        
                    }          
                }
            }     
        }
        if(hex_num){
            hex_num = false; result += ch; num.clear(); temp.clear();
        }
        else{
            result += temp; num.clear(); temp.clear();
        }
    }
    return result;
}

int checkSequence(string inputStr, unsigned long begin_byte, char* filename)
{
    string tempStr, substr1, substr2, targetSeq, targetName;
    unsigned long byteNum = 0;
    unsigned int seqSize = 0;
    size_t find_pos = 0; 
    int match = 0;
    // scan and see if there has match. For one line, each time check 
    // one sequence, and then check next sequence and so on 
    for(int i=0; i<mList.getSize(); i++){
        tempStr = inputStr;   
        targetSeq =  mList.getSequence(mList.token(i));
        if(targetSeq.empty()){
            match = -1;
            cerr<<"index refer to an invalid range"<<endl;
            return match;
        }
        targetName = mList.getName(mList.token(i));
        if(targetName.empty()){
            match = -1;
            cerr<<"index refer to am invalid range"<<endl;
            return match;
        }
        // adjust the byte position
        byteNum = begin_byte;
        seqSize = targetSeq.size();   
        
        // start scan
        while((tempStr.find(targetSeq)!= string::npos)){
            find_pos = tempStr.find(targetSeq);
            found = true;
            match = 1;
  //          byteNum += find_pos;          // update the position 
           // substr1 = tempStr.substr(0, find_pos + seqSize);
            substr1 = tempStr.substr(0, find_pos+1);
       //     substr2 = tempStr.substr(find_pos + seqSize);
            substr2 = tempStr.substr(find_pos+1);
            
            if(s_flag){
                if(!q_flag)
                    cout<<filename<<": "<<targetName<<" found at byte "<<byteNum + find_pos<<endl;            
                return match;
            }
            else{
                if(!q_flag)
                    cout<<filename<<": "<<targetName<<" found at byte "<<byteNum + find_pos<<endl; 
                tempStr = substr2;
                byteNum = byteNum + (find_pos + 1);
            }
        }
    }
    return match;
}

// functions from the MalList class 
bool MalList::checkMalNum(int malNum){
    malNum = malNum - 0x1221;
    return (malNum>=0 && malNum <= listSize);
}

void MalList::updateSize(){
    listSize = malName.size();
}

unsigned int MalList::getSize(){
    return listSize;
}

void MalList::addName(string name){
    malName.push_back(name);
}

void MalList::addSequence(string seq){
    malSeq.push_back(seq);
}

string MalList::getName(int malNum){
    if(checkMalNum(malNum))
        return malName.at(malNum-0x1221);
    else
        return NULL;
}

string MalList::getSequence(int malNum){
    if(checkMalNum(malNum))
        return malSeq.at(malNum-0x1221);
    else 
        return NULL;
}

int MalList::token(int num){
    return (num + 0x1221);
}
