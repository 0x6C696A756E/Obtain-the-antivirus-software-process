#define _CRT_SECURE_NO_WARNINGS
/*
获取系统已安装的杀毒软件
*/
#include <windows.h> //必要头文件
#include <tlhelp32.h>	//必要头文件
#include <iostream>
#include <stdio.h>//printf
#include <map>
using namespace std;

//自定义策略支持 查找key 不区分大小写
struct ci_less {
	struct nocase_compare {
		bool operator() (const unsigned char& c1, const unsigned char& c2) const {
			return tolower(c1) < tolower(c2);
		}
	};
	bool operator() (const std::string& s1, const std::string& s2) const {
		return std::lexicographical_compare
		(s1.begin(), s1.end(),   // source range
			s2.begin(), s2.end(),   // dest range
			nocase_compare());
	}
};

multimap<string, string, ci_less> AntivirusMultimap;//杀毒软件初始化表
int Antiviruscount = 0;//杀毒软件进程个数
HANDLE consolehwnd;//创建控制台句柄 实现输出颜色字体
//函数申明
string WideCharToMultiByte(const wchar_t* wideString);//宽字节类型转普通string
void AntivirusMultimap_init();//杀毒软件初始化函数

int main()
{
	printf("\n");
	printf("******************************************************************************\n");
	printf("【+】快速查找已安装的杀毒软件进程\n");
	printf("【+】https://github.com/0x6C696A756E/Obtain-the-antivirus-software-process\n");
	printf("【+】https://blog.csdn.net/qq_29826869\n");
	printf("【+】- 0x6C696A756E -\n");
	printf("【+】Date 2023/9/19\n");
	printf("******************************************************************************\n");
	printf("\n");
	consolehwnd = GetStdHandle(STD_OUTPUT_HANDLE);//实例化句柄
	//杀毒软件初始化
	AntivirusMultimap_init();
	// 获取系统进程快照
	HANDLE processHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (processHandle == INVALID_HANDLE_VALUE)
	{
		printf("获取系统进程快照错误\n");
		return 0;
	}
	PROCESSENTRY32 processentry32;
	processentry32.dwSize = sizeof(processentry32);
	// 枚举快照的第一个进程
	BOOL bProcess = Process32First(processHandle, &processentry32);
	while (bProcess)
	{
		//sprintf(buff, "进程名称：%ls  进程号：%lu\n", processentry32.szExeFile, processentry32.th32ProcessID);
		string Process_name = WideCharToMultiByte(processentry32.szExeFile);//processentry32.szExeFile 是宽字节数组
		auto range = AntivirusMultimap.equal_range(Process_name);
		for (auto it = range.first; it != range.second; ++it) {
			SetConsoleTextAttribute(consolehwnd, FOREGROUND_RED);//设置红色
			printf("[+] %s - %s - %lu\n", it->first.c_str(), it->second.c_str(), processentry32.th32ProcessID);
			SetConsoleTextAttribute(consolehwnd, 7); // 恢复控制台默认颜色
			Antiviruscount++;//发现杀毒进程 自增1
		}
		bProcess = Process32Next(processHandle, &processentry32);
	}
	
	if (!Antiviruscount) {
		printf("\n");
		SetConsoleTextAttribute(consolehwnd, FOREGROUND_GREEN);//设置绿色
		printf("[+] 报告首长 暂未发现杀毒软件进程\n");
		SetConsoleTextAttribute(consolehwnd, 7); // 恢复控制台默认颜色
	}
	else
	{
		printf("\n");
		SetConsoleTextAttribute(consolehwnd, FOREGROUND_RED);//设置红色
		printf("[+] 报告首长 共发现：%d 个与杀毒软件相关进程 请小心行事！\n", Antiviruscount);
		SetConsoleTextAttribute(consolehwnd, 7); // 恢复控制台默认颜色
	}
	CloseHandle(processHandle);
	return 0;
}

//宽字节wchar_t 转普通窄字节string 
//形参为wchar_t* 指针类型 直接传入宽字节数组名就行，因为数组名就是指向首地址的指针
string WideCharToMultiByte(const wchar_t* wideString)
{
	int bufferSize = WideCharToMultiByte(CP_UTF8, 0, wideString, -1, nullptr, 0, nullptr, nullptr);
	char* buffer = new char[bufferSize];
	string result;
	WideCharToMultiByte(CP_UTF8, 0, wideString, -1, buffer, bufferSize, nullptr, nullptr);
	result = buffer;
	delete[] buffer;
	return result;
}

//杀毒软件初始化
void AntivirusMultimap_init() {
	AntivirusMultimap = { 
		{"360tray.exe","360安全卫士 安全防护中心模块"},
		{"360sd.exe","360杀毒 主程序"},
		{"360rp.exe","360杀毒 实时监控"},
		{"360rps.exe","360杀毒 服务程序"},
		{"safesvr.exe","360安全卫士"},
		{"ZhuDongFangYu.exe","360主动防御服务模块"},
		{"a2guard.exe","a-squared杀毒"},
		{"ad-watch.exe","Lavasoft杀毒"},
		{"cleaner8.exe","TheCleaner杀毒"},
		{"vba32lder.exe","vb32杀毒"},
		{"MongoosaGUI.exe","Mongoosa杀毒"},
		{"CorantiControlCenter32.exe","Coranti2012杀毒"},
		{"F-PROT.EXE","F-PROT杀毒"},
		{"CMCTrayIcon.exe","CMC杀毒"},
		{"K7TSecurity.exe","K7杀毒"},
		{"UnThreat.exe","UnThreat杀毒"},
		{"CKSoftShiedAntivirus4.exe","ShieldAntivirus杀毒"},
		{"AVWatchService.exe","VIRUSfighter杀毒"},
		{"ArcaTasksService.exe","ArcaVir杀毒"},
		{"iptray.exe","Immunet杀毒"},
		{"PSafeSysTray.exe","PSafe杀毒"},
		{"nspupsvc.exe","nProtect杀毒"},
		{"SpywareTerminatorShield.exe","SpywareTerminator杀毒"},
		{"BKavService.exe","Bkav杀毒"},
		{"MsMpEng.exe","MicrosoftSecurityEssentials"},
		{"SBAMSvc.exe","VIPRE"},
		{"ccSvcHst.exe","Norton杀毒"},
		{"f-secure.exe","冰岛"},
		{"avp.exe","卡巴斯基"},
		{"KvMonXP.exe","江民杀毒"},
		{"RavMonD.exe","瑞星杀毒"},
		{"Mcshield.exe","麦咖啡"},
		{"egui.exe","NOD32"},
		{"kxetray.exe","金山毒霸"},
		{"knsdtray.exe","可牛杀毒"},
		{"avcenter.exe","Avira(小红伞)"},
		{"ashDisp.exe","Avast网络安全"},
		{"rtvscan.exe","诺顿杀毒"},
		{"ksafe.exe","金山卫士"},
		{"QQPCRTP.exe","QQ电脑管家"},
		{"Miner.exe","流量矿石"},
		{"AYAgent.aye","韩国胶囊"},
		{"patray.exe","安博士"},
		{"V3Svc.exe","安博士V3"},
		{"avgwdsvc.exe","AVG杀毒"},
		{"ccSetMgr.exe","赛门铁克"},
		{"QUHLPSVC.EXE","QUICKHEAL杀毒"},
		{"mssecess.exe","微软杀毒"},
		{"SavProgress.exe","Sophos杀毒"},
		{"fsavgui.exe","F-Secure杀毒"},
		{"vsserv.exe","比特梵德"},
		{"remupd.exe","熊猫卫士"},
		{"FortiTray.exe","飞塔"},
		{"parmor.exe","木马克星"},
		{"beikesan.exe","贝壳云安全"},
		{"KSWebShield.exe","金山网盾"},
		{"TrojanHunter.exe","木马猎手"},
		{"GG.exe","巨盾网游安全盾"},
		{"adam.exe","绿鹰安全精灵"},
		{"AST.exe","超级巡警"},
		{"ananwidget.exe","墨者安全专家"},
		{"AVK.exe","GData"},
		{"ccapp.exe","SymantecNorton"},
		{"avg.exe","AVGAnti-Virus"},
		{"spidernt.exe","Dr.web"},
		{"Mcshield.exe","Mcafee"},
		{"avgaurd.exe","AviraAntivir"},
		{"F-PROT.exe","F-ProtAntiVirus"},
		{"vsmon.exe","ZoneAlarm"},
		{"avp.exee","Kaspersky"},
		{"cpf.exe","Comodo"},
		{"outpost.exe","OutpostFirewall"},
		{"rfwmain.exe","瑞星防火墙"},
		{"kpfwtray.exe","金山网镖"},
		{"FYFireWall.exe","风云防火墙"},
		{"MPMon.exe","微点主动防御"},
		{"pfw.exe","天网防火墙"},
		{"S.exe","在抓鸡"},
		{"1433.exe","在扫1433"},
		{"DUB.exe","在爆破"},
		{"ServUDaemon.exe","发现S-U"},
		{"BaiduSdSvc.exe","百度杀软"},
		{"safedog.exe","安全狗-WAF"},
		{"SafeDogGuardCenter.exe","安全狗-WAF"},
		{"safedogupdatecenter.exe","安全狗-WAF"},
		{"safedogguardcenter.exe","安全狗-WAF"},
		{"SafeDogSiteIIS.exe","安全狗-WAF"},
		{"SafeDogTray.exe","安全狗-WAF"},
		{"SafeDogServerUI.exe","安全狗-WAF"},
		{"D_Safe_Manage.exe","D盾-WAF"},
		{"d_manage.exe","D盾-WAF"},
		{"yunsuo_agent_service.exe","云锁-WAF"},
		{"yunsuo_agent_daemon.exe","云锁-WAF"},
		{"HwsPanel.exe","护卫神 -WAF入侵防护系统(状态托盘)"},
		{"hws_ui.exe","护卫神 - WAF 入侵防护系统"},
		{"hws.exe","护卫神 - WAF 入侵防护系统 服务处理程序"},
		{"hwsd.exe","护卫神 - WAF 入侵防护系统 监控组件"},
		{"hipstray.exe","火绒杀毒"},
		{"HipsMain.exe","火绒杀毒"},
		{"wsctrl.exe","火绒杀毒"},
		{"wsctrlsvc.exe","火绒杀毒"},
		{"usysdiag.exe","火绒杀毒"},
		{"HipsDaemon.exe","火绒杀毒"},
		{"TMBMSRV.exe","趋势科技"},
		{"ntrtscan.exe","趋势科技"},
		{"PCCNTMON.exe","趋势科技"},
		{"TMLISTEN.exe","趋势科技"}
	};
}