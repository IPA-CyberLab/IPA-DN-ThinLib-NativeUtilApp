// IPA-DN-ThinLib-NativeUtilApp Source Code
// 
// License: The Apache License, Version 2.0
// https://www.apache.org/licenses/LICENSE-2.0
// 
// Copyright (c) IPA CyberLab of Industrial Cyber Security Center.
// Copyright (c) NTT-East Impossible Telecom Mission Group.
// Copyright (c) Daiyuu Nobori.
// Copyright (c) SoftEther VPN Project, University of Tsukuba, Japan.
// Copyright (c) SoftEther Corporation.
// Copyright (c) all contributors on IPA-DN-ThinLib Library and SoftEther VPN Project in GitHub.
// 
// All Rights Reserved.
// 
// DISCLAIMER
// ==========
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// 
// THIS SOFTWARE IS DEVELOPED IN JAPAN, AND DISTRIBUTED FROM JAPAN, UNDER
// JAPANESE LAWS. YOU MUST AGREE IN ADVANCE TO USE, COPY, MODIFY, MERGE, PUBLISH,
// DISTRIBUTE, SUBLICENSE, AND/OR SELL COPIES OF THIS SOFTWARE, THAT ANY
// JURIDICAL DISPUTES WHICH ARE CONCERNED TO THIS SOFTWARE OR ITS CONTENTS,
// AGAINST US (IPA, NTT-EAST, SOFTETHER PROJECT, SOFTETHER CORPORATION, DAIYUU NOBORI
// OR OTHER SUPPLIERS), OR ANY JURIDICAL DISPUTES AGAINST US WHICH ARE CAUSED BY ANY
// KIND OF USING, COPYING, MODIFYING, MERGING, PUBLISHING, DISTRIBUTING, SUBLICENSING,
// AND/OR SELLING COPIES OF THIS SOFTWARE SHALL BE REGARDED AS BE CONSTRUED AND
// CONTROLLED BY JAPANESE LAWS, AND YOU MUST FURTHER CONSENT TO EXCLUSIVE
// JURISDICTION AND VENUE IN THE COURTS SITTING IN TOKYO, JAPAN. YOU MUST WAIVE
// ALL DEFENSES OF LACK OF PERSONAL JURISDICTION AND FORUM NON CONVENIENS.
// PROCESS MAY BE SERVED ON EITHER PARTY IN THE MANNER AUTHORIZED BY APPLICABLE
// LAW OR COURT RULE.
// 
// USE ONLY IN JAPAN. DO NOT USE THIS SOFTWARE IN ANOTHER COUNTRY UNLESS YOU HAVE
// A CONFIRMATION THAT THIS SOFTWARE DOES NOT VIOLATE ANY CRIMINAL LAWS OR CIVIL
// RIGHTS IN THAT PARTICULAR COUNTRY. USING THIS SOFTWARE IN OTHER COUNTRIES IS
// COMPLETELY AT YOUR OWN RISK. IPA AND NTT-EAST HAS DEVELOPED AND
// DISTRIBUTED THIS SOFTWARE TO COMPLY ONLY WITH THE JAPANESE LAWS AND EXISTING
// CIVIL RIGHTS INCLUDING PATENTS WHICH ARE SUBJECTS APPLY IN JAPAN. OTHER
// COUNTRIES' LAWS OR CIVIL RIGHTS ARE NONE OF OUR CONCERNS NOR RESPONSIBILITIES.
// WE HAVE NEVER INVESTIGATED ANY CRIMINAL REGULATIONS, CIVIL LAWS OR
// INTELLECTUAL PROPERTY RIGHTS INCLUDING PATENTS IN ANY OF OTHER 200+ COUNTRIES
// AND TERRITORIES. BY NATURE, THERE ARE 200+ REGIONS IN THE WORLD, WITH
// DIFFERENT LAWS. IT IS IMPOSSIBLE TO VERIFY EVERY COUNTRIES' LAWS, REGULATIONS
// AND CIVIL RIGHTS TO MAKE THE SOFTWARE COMPLY WITH ALL COUNTRIES' LAWS BY THE
// PROJECT. EVEN IF YOU WILL BE SUED BY A PRIVATE ENTITY OR BE DAMAGED BY A
// PUBLIC SERVANT IN YOUR COUNTRY, THE DEVELOPERS OF THIS SOFTWARE WILL NEVER BE
// LIABLE TO RECOVER OR COMPENSATE SUCH DAMAGES, CRIMINAL OR CIVIL
// RESPONSIBILITIES. NOTE THAT THIS LINE IS NOT LICENSE RESTRICTION BUT JUST A
// STATEMENT FOR WARNING AND DISCLAIMER.
// 
// READ AND UNDERSTAND THE 'WARNING.TXT' FILE BEFORE USING THIS SOFTWARE.
// SOME SOFTWARE PROGRAMS FROM THIRD PARTIES ARE INCLUDED ON THIS SOFTWARE WITH
// LICENSE CONDITIONS WHICH ARE DESCRIBED ON THE 'THIRD_PARTY.TXT' FILE.
// 
// ---------------------
// 
// If you find a bug or a security vulnerability please kindly inform us
// about the problem immediately so that we can fix the security problem
// to protect a lot of users around the world as soon as possible.
// 
// Our e-mail address for security reports is:
// daiyuu.securityreport [at] dnobori.jp
// 
// Thank you for your cooperation.


#define	VPN_EXE
#define VARS_DEFINE_PATCH

#include <GlobalConst.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <Mayaqua/Mayaqua.h>
#include <Cedar/Cedar.h>
#include "NativeUtilApp.h"
#include "Vars/VarsActivePatch.h"

extern bool g_debug;

typedef struct UDPBST
{
	IP ip;
	UINT port;
	UINT size;
	bool rand_flag;
} UDPBST;

#ifdef	UNIX_LINUX

struct mmsghdr2 {
	struct msghdr msg_hdr;
	unsigned int  msg_len;
};

#endif	// UNIX_LINUX





UINT dbg_tick_count = 0;
UINT64 dbg_tick_now = 0;
UINT dbg_last_diff = 0;
UINT dbg_diff_max = 0;

void debug_sock_thread(THREAD *thread, void *param)
{
#ifdef OS_WIN32
	MsSetThreadPriorityRealtime();
#else
	UnixSetThreadPriorityRealtime();
#endif // OS_WIN32

	SOCK *s = param;

	char *str = "Hello!! \r\n>";

	SendAll(s, str, StrLen(str), false);

	UINT counter = 0;

	/*while (true)
	{
		UCHAR c = 0;
		if (RecvAll(s, &c, 1, false) == false)
		{
			break;
		}

		if (c == 'a')
		{
			char *ok_str = "\r\nOK!\r\n";
			SendAll(s, ok_str, StrLen(ok_str), false);
			CrashNow();
		}

		counter++;
		char tmp[MAX_PATH] = CLEAN;

		Format(tmp, sizeof(tmp), "\r\n%u>", counter);
		SendAll(s, tmp, StrLen(tmp), false);
	}*/

	while (true)
	{
		char tmp[MAX_PATH] = CLEAN;
		Format(tmp, sizeof(tmp), "%u    %I64u   diff = %u  max = %u\r\n", dbg_tick_count, dbg_tick_now, dbg_last_diff, dbg_diff_max);
		if (SendAll(s, tmp, StrLen(tmp), false) == false)
		{
			break;
		}

		SleepThread(100);
	}

	Disconnect(s);
	ReleaseSock(s);
}

void debug_thread(THREAD *thread, void *param)
{
#ifdef OS_WIN32
	MsSetThreadPriorityRealtime();
#else
	UnixSetThreadPriorityRealtime();
#endif // OS_WIN32

	SOCK *s = Listen(1234);
	if (s == NULL)
	{
		Print("Listen error\n");
		return;
	}

	while (true)
	{
		SOCK *a = Accept(s);

		THREAD *t = NewThread(debug_sock_thread, a);

		ReleaseThread(t);
	}
}

void check_stall_thread(THREAD *thread, void *param)
{
#ifdef OS_WIN32
	MsSetThreadPriorityRealtime();
#else
	UnixSetThreadPriorityRealtime();
#endif // OS_WIN32

	UINT64 last = 0;

	UINT sleep_span = 100;

	while (true)
	{
		UINT64 now = 0;

#ifdef OS_WIN32
		now = TickHighres64();
#else
		struct timespec t = CLEAN;
		clock_gettime(CLOCK_MONOTONIC, &t);
		now = ((UINT64)((UINT32)t.tv_sec)) * 1000LL + (UINT64)t.tv_nsec / 1000000LL;
#endif // OS_WIN32


		dbg_tick_now = now;
		dbg_tick_count++;

		if (last != 0)
		{
			dbg_last_diff = (UINT)(now - last);
			dbg_diff_max = MAX(dbg_diff_max, dbg_last_diff);
			//if (dbg_last_diff >= 100)
			{
				if (dbg_last_diff >= 5000)
				{
					char tmp[MAX_PATH] = CLEAN;
					Format(tmp, sizeof(tmp), "dbg_last_diff = %u\n", dbg_last_diff);
					AbortExitEx(tmp);
				}

				UINT a = dbg_last_diff;
				a = MAX(a, sleep_span);
				a -= sleep_span;

				Print("diff = %u\n", a);
			}
		}

		last = now;

		SleepThread(sleep_span);
	}
}

bool heavy_thread_start_flag = false;

LOCK *heavy_lock;

void heavy_thread_proc(THREAD *thread, void *param)
{
	UINT i = (UINT)(UINT64)param;
	while (heavy_thread_start_flag == false)
	{
		SleepThread(100);
	}

	if ((i % 2) == 0 || true)
	{
		while (true)
		{
			//SleepThread(100);
			Lock(heavy_lock);
			{
				UINT j;
				UINT len = 10;
				for (j = 0;j < len;j++)
				{
					DoNothing();
				}

				DoNothing();
			}
			Unlock(heavy_lock);
			
			UINT j;
			UINT len = rand() % 100;
			for (j = 0;j < len;j++)
			{
				DoNothing();
			}
		}
	}
	else
	{
		while (true)
		{
			DoNothing();
		}
	}
}

void heavy_test_main(UINT num_threads)
{
	heavy_lock = NewLock();

	if (num_threads == 0)
	{
		num_threads = 1;
	}

	Print("Heavy test init (num_threads = %u) ...\n", num_threads);
	NewThread(check_stall_thread, NULL);
	NewThread(debug_thread, NULL);

	Print("Starting %u threads ...\n", num_threads);
	UINT i;
	for (i = 0;i < num_threads;i++)
	{
		NewThread(heavy_thread_proc, (void *)(UINT64)i);
		if ((i % 100) == 0)
		{
			Print("Thread %u\n", i);
		}
	}
	Print("All %u threads started. Ok.\n", num_threads);
	SleepThread(100);
	heavy_thread_start_flag = true;
	SleepThread(INFINITE);
}

void heavy_test(UINT argc, char **argv)
{
	UINT num_threads = 1000;
	if (argc >= 1)
	{
		num_threads = ToInt(argv[0]);
	}

	heavy_test_main(num_threads);
}



char* Dev_GetFirstFilledStrFromBuf(BUF* buf)
{
	if (buf == NULL)
	{
		return CopyStr("");
	}

	UINT size = buf->Size + 8;
	char* tmp = ZeroMalloc(size);
	Copy(tmp, buf->Buf, buf->Size);

	char* ret = GetFirstFilledStrFromStr(tmp);

	Free(tmp);

	return ret;
}



typedef struct SSL_SERVER_BENCH
{
	X* testcert_01_chain1;
	X* testcert_01_chain2;
	X* testcert_03_host;
	K* testcert_03_host_key;

	X* widecert_01_controller;
	K* widecert_01_controller_key;

	CERTS_AND_KEY* certs_and_key_for_sni;

	LIST* SockThreadList;

	COUNTER* CurrentConnections;
	COUNTER* CurrentSslInProgress;
	COUNTER* TotalSslOk;
	COUNTER* TotalSslError;

	UINT mode;

	bool Halt;
	EVENT* HaltEvent;
} SSL_SERVER_BENCH;

typedef struct SSL_SERVER_BENCH_STAT
{
	UINT CurrentConnections;
	UINT CurrentSslInProgress;
	UINT TotalSslOk;
	UINT TotalSslError;
	UINT64 Tick;
} SSL_SERVER_BENCH_STAT;

void sslserverbench_accepted(SSL_SERVER_BENCH* svr, SOCK* s)
{
	SetTimeout(s, CONNECTING_TIMEOUT);

	CERTS_AND_KEY* ssl_additional_certs_array[2] = CLEAN;
	UINT num_certs_array_items = 0;

	CERTS_AND_KEY* web_socket_certs = NULL;

	if (svr->mode != 0)
	{
		web_socket_certs = svr->certs_and_key_for_sni;
		AddRef(web_socket_certs->Ref);

		web_socket_certs->DetermineUseCallback = WtgDetermineWebSocketSslCertUseCallback;
		ssl_additional_certs_array[num_certs_array_items] = web_socket_certs;
		num_certs_array_items++;
	}

	Inc(svr->CurrentSslInProgress);
	if (StartSSLEx2(s, svr->widecert_01_controller, svr->widecert_01_controller_key, true, 0, NULL, ssl_additional_certs_array, num_certs_array_items, NULL, false))
	{
		Dec(svr->CurrentSslInProgress);
		Inc(svr->TotalSslOk);

		while (true)
		{
			UCHAR data[128] = CLEAN;

			if (SendAll(s, data, sizeof(data), true) == false)
			{
				break;
			}

			if (RecvAll(s, data, sizeof(data), true) == false)
			{
				break;
			}
		}
	}
	else
	{
		Dec(svr->CurrentSslInProgress);
		Inc(svr->TotalSslError);
	}

	ReleaseCertsAndKey(web_socket_certs);
}

void sslserverbench_print_stat_thread(THREAD* thread, void* param)
{
	SSL_SERVER_BENCH* svr = (SSL_SERVER_BENCH*)param;

	SSL_SERVER_BENCH_STAT last = CLEAN;

	last.Tick = Tick64();

	UINT num = 0;

	while (svr->Halt == false)
	{
		num++;

		Wait(svr->HaltEvent, 1000);
		if (svr->Halt) break;

		SSL_SERVER_BENCH_STAT current = CLEAN;

		current.CurrentConnections = Count(svr->CurrentConnections);
		current.CurrentSslInProgress = Count(svr->CurrentSslInProgress);
		current.TotalSslOk = Count(svr->TotalSslOk);
		current.TotalSslError = Count(svr->TotalSslError);
		current.Tick = Tick64();

		if (current.Tick > last.Tick)
		{
			SSL_SERVER_BENCH_STAT diff = CLEAN;

			diff.CurrentConnections = current.CurrentConnections - last.CurrentConnections;
			diff.CurrentSslInProgress = current.CurrentSslInProgress - last.CurrentSslInProgress;
			diff.TotalSslOk = current.TotalSslOk - last.TotalSslOk;
			diff.TotalSslError = current.TotalSslError - last.TotalSslError;
			diff.Tick = current.Tick - last.Tick;

			double total_ssl_ok_avr = (double)diff.TotalSslOk * 1000.0 / (double)diff.Tick;
			double total_ssl_err_svr = (double)diff.TotalSslError * 1000.0 / (double)diff.Tick;

			Print("Report #%u: SSL_OK/sec: %.1f, SSL_ERR/sec: %.1f, TCP: %u, SSLNego: %u\n",
				num, total_ssl_ok_avr, total_ssl_err_svr, current.CurrentConnections, current.CurrentSslInProgress);

			last = current;
		}
	}
}

void sslserverbench_thread(THREAD* thread, void* param)
{
	TCP_ACCEPTED_PARAM* accepted_param;
	LISTENER* r;
	SOCK* s;
	SSL_SERVER_BENCH* svr;
	// 引数チェック
	if (thread == NULL || param == NULL)
	{
		return;
	}

	accepted_param = (TCP_ACCEPTED_PARAM*)param;
	r = accepted_param->r;
	s = accepted_param->s;
	AddRef(r->ref);
	AddRef(s->ref);
	svr = (SSL_SERVER_BENCH*)r->ThreadParam;

	AddSockThread(svr->SockThreadList, s, thread);

	NoticeThreadInit(thread);
	AcceptInitEx2(s, true, false);

	Inc(svr->CurrentConnections);

	sslserverbench_accepted(svr, s);

	Dec(svr->CurrentConnections);

	DelSockThread(svr->SockThreadList, s);

	ReleaseSock(s);
	ReleaseListener(r);
}

void sslserverbench_test(UINT num, char** arg)
{
	OSRestorePriority();

	if (num < 1)
	{
		Print("Usage: sslserverbench <TCP_Port> [mode=0]\n");
		Print("Modes: 0: Simple\n");
		Print("       1: SNI aware\n");
		return;
	}

	g_debug = false;

	CEDAR* cedar;

	char* port_str = arg[0];
	UINT port = ToInt(port_str);

	SSL_SERVER_BENCH* svr = ZeroMalloc(sizeof(SSL_SERVER_BENCH));

	if (num >= 2)
	{
		svr->mode = ToInt(arg[1]);
	}

	svr->HaltEvent = NewEvent();

	svr->testcert_01_chain1 = FileToX("|TestCert_01_Chain1.cer");
	svr->testcert_01_chain2 = FileToX("|TestCert_02_Chain2.cer");
	svr->testcert_03_host = FileToX("|TestCert_03_Host.cer");
	svr->testcert_03_host_key = FileToK("|TestCert_03_Host.key", true, NULL);
	svr->widecert_01_controller = FileToX("|WideCert_01_Controller.cer");
	svr->widecert_01_controller_key = FileToK("|WideCert_01_Controller.key", true, NULL);

	svr->CurrentConnections = NewCounter();
	svr->CurrentSslInProgress = NewCounter();
	svr->TotalSslError = NewCounter();
	svr->TotalSslOk = NewCounter();

	if (svr->testcert_01_chain1 == NULL || svr->testcert_01_chain2 == NULL || svr->testcert_03_host == NULL ||
		svr->testcert_03_host_key == NULL || svr->widecert_01_controller == NULL || svr->widecert_01_controller_key == NULL)
	{
		Print("Load cert failed.\n");
		exit(1);
	}

	THREAD* stat_thread = NewThread(sslserverbench_print_stat_thread, svr);

	LIST* chain_list = NewList(NULL);
	Add(chain_list, svr->testcert_03_host);
	Add(chain_list, svr->testcert_01_chain1);
	Add(chain_list, svr->testcert_01_chain2);

	svr->certs_and_key_for_sni = NewCertsAndKeyFromObjects(chain_list, svr->testcert_03_host_key, false);

	svr->SockThreadList = NewSockThreadList();

	cedar = NewCedar(NULL, NULL);

	DisableDosProtect();

	LISTENER* listener = NewListenerEx(cedar, LISTENER_TCP, port, sslserverbench_thread, svr);

	Print("Enter to exit>");
	GetLine(NULL, 0);

	Print("Exiting...\n");

	svr->Halt = true;
	Set(svr->HaltEvent);

	StopAllListener(cedar);
	StopListener(listener);
	ReleaseListener(listener);

	FreeSockThreadList(svr->SockThreadList);

	ReleaseCedar(cedar);

	ReleaseCertsAndKey(svr->certs_and_key_for_sni);

	FreeX(svr->testcert_01_chain1);
	FreeX(svr->testcert_01_chain2);
	FreeX(svr->testcert_03_host);
	FreeK(svr->testcert_03_host_key);
	FreeX(svr->widecert_01_controller);
	FreeK(svr->widecert_01_controller_key);

	ReleaseList(chain_list);

	svr->Halt = true;
	Set(svr->HaltEvent);
	WaitThread(stat_thread, INFINITE);
	ReleaseThread(stat_thread);

	DeleteCounter(svr->CurrentConnections);
	DeleteCounter(svr->CurrentSslInProgress);
	DeleteCounter(svr->TotalSslError);
	DeleteCounter(svr->TotalSslOk);

	ReleaseEvent(svr->HaltEvent);

	Free(svr);
}

char sslclientbench_target_str[MAX_SIZE] = CLEAN;

typedef struct SSL_CLIENT_BENCH_CTX
{
	UINT ThreadId;
} SSL_CLIENT_BENCH_CTX;

UINT sslclientbench_total_ok = 0;
UINT sslclientbench_total_tcp_error = 0;
UINT sslclientbench_total_ssl_error = 0;

void sslclientbench_do_main(SSL_CLIENT_BENCH_CTX *c)
{
	CHAR target[MAX_PATH] = CLEAN;

	StrCpy(target, sizeof(target), sslclientbench_target_str);

	if (IsFilledStr(target))
	{
		char* host = NULL;
		UINT port = 0;

		if (ParseHostPort(target, &host, &port, 443))
		{
			SOCK* s = Connect(host, port);
			if (s == NULL)
			{
				Print("Thread %u: TCP Connect failed to %s:%u\n", c->ThreadId, host, port);

				sslclientbench_total_tcp_error++;
			}
			else
			{
				Print("Thread %u: TCP OK.\n", c->ThreadId, host, port);

				SetTimeout(s, CONNECTING_TIMEOUT);

				if (StartSSLEx(s, NULL, NULL, true, CONNECTING_TIMEOUT, target) == false)
				{
					Print("Thread %u: StartSSLEx Error to %s:%u\n", c->ThreadId, host, port);

					sslclientbench_total_ssl_error++;
				}
				else
				{
					Print("Thread %u: SSL OK.\n", c->ThreadId, host, port);

					sslclientbench_total_ok++;

					UCHAR data[128] = CLEAN;

					RecvAll(s, data, sizeof(data), true);
				}

				Disconnect(s);
				ReleaseSock(s);
			}

			Free(host);
		}
	}
}

void sslclientbench_thread(THREAD* thread, void* param)
{
	SSL_CLIENT_BENCH_CTX* c = (SSL_CLIENT_BENCH_CTX*)param;

	while (true)
	{
		SleepThread(Rand32() % 1000);

		sslclientbench_do_main(c);
	}
}

void sslclientbench_test(UINT num, char** arg)
{
	OSRestorePriority();

	UINT num_threads = 256;

	sslclientbench_total_ok = 0;
	sslclientbench_total_tcp_error = 0;
	sslclientbench_total_ssl_error = 0;

	if (num < 1)
	{
		Print("Usage: sslclientbench <DEST_SERVER>[:PORT=443] or <TARGET_TXT_URL>\n");
		return;
	}

	g_debug = false;

	char* host_or_url = arg[0];
	bool is_url = false;

	if (StartWith(host_or_url, "http://") || StartWith(host_or_url, "https://"))
	{
		is_url = true;
	}
	else
	{
		StrCpy(sslclientbench_target_str, sizeof(sslclientbench_target_str), host_or_url);
	}

	UINT i;
	for (i = 0;i < num_threads;i++)
	{
		SSL_CLIENT_BENCH_CTX* c = ZeroMalloc(sizeof(SSL_CLIENT_BENCH_CTX));
		c->ThreadId = i + 1;
		THREAD* t = NewThread(sslclientbench_thread, c);
	}

	while (true)
	{
		UINT err = ERR_NO_ERROR;

		if (is_url)
		{
			BUF* body = HttpDownload(host_or_url, NULL, NULL, NULL, 5 * 1000, 5 * 1000, &err, false, NULL, 0, NULL, 65536);

			if (body == NULL)
			{
				Print("Failed download from %s\n", host_or_url);
			}
			else
			{
				char* recv_url = Dev_GetFirstFilledStrFromBuf(body);

				if (StrCmp(recv_url, sslclientbench_target_str) != 0)
				{
					StrCpy(sslclientbench_target_str, sizeof(sslclientbench_target_str), recv_url);
					Print("Target URL Changed: %s\n", sslclientbench_target_str);
				}

				Free(recv_url);
				FreeBuf(body);
			}
		}

		Print("Total OK: %u, TCP Error: %u, SSL Error: %u\n",
			sslclientbench_total_ok,
			sslclientbench_total_tcp_error,
			sslclientbench_total_ssl_error);

		SleepThread(Rand32() % 1000);
	}
}

volatile UINT udpbench_target_pps = 0;
volatile UINT64 udpbench_total_packets = 0;
volatile UINT udpbench_num_packets_per_wait = 0;
volatile UINT udpbench_sleep_interval = 10;

void udpbench_thread(THREAD* thread, void* param)
{
#ifdef	UNIX_LINUX
	bool is_ipv6;
	UDPBST* st;
	SOCK* s;
	UCHAR* buf;
	UINT size;
	UINT i;
	int socket;
	struct sockaddr_in addr;
	struct sockaddr_in6 addr6;
	struct iovec msg_iov;
	struct msghdr msg_header;
	UINT count = 1024;
	struct mmsghdr2* msgvec = NULL;
	volatile static UINT dst_rand_addr = 0;
	// DNS A: host0000535677.ddns_example.net.
	char *dns_packet_hex = "0003000000010000000000000574657374310c64646e735f6578616d706c65036e65740000010001";

	BUF* dns_packet_buf = StrToBin(dns_packet_hex);

	Zero(&msg_iov, sizeof(msg_iov));
	Zero(&msg_header, sizeof(msg_header));

	st = (UDPBST*)param;

	is_ipv6 = IsIP6(&st->ip);

	s = NewUDPEx(0, is_ipv6);

	size = st->size;
	buf = Malloc(size);

	Rand(buf, size);

	if (size == dns_packet_buf->Size)
	{
		Copy(buf, dns_packet_buf->Buf, dns_packet_buf->Size);
	}

	if (is_ipv6 == false)
	{
		Zero(&addr, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_port = htons((USHORT)st->port);
		IPToInAddr(&addr.sin_addr, &st->ip);
	}
	else
	{
		Zero(&addr6, sizeof(addr6));
		addr6.sin6_family = AF_INET6;
		addr6.sin6_port = htons((USHORT)st->port);
		IPToInAddr6(&addr6.sin6_addr, &st->ip);
	}

	socket = s->socket;

	msgvec = ZeroMalloc(sizeof(struct mmsghdr2) * count);
	for (i = 0;i < count;i++)
	{
		struct msghdr* msg_header;
		struct iovec* msg_iov;

		msg_iov = ZeroMalloc(sizeof(struct iovec));
		msg_iov->iov_base = Clone(buf, size);
		msg_iov->iov_len = size;

		msg_header = &msgvec[i].msg_hdr;

		if (is_ipv6 == false)
		{
			msg_header->msg_name = (struct sockaddr*)Clone(&addr, sizeof(struct sockaddr_in));
			msg_header->msg_namelen = sizeof(addr);
		}
		else
		{
			msg_header->msg_name = (struct sockaddr*)Clone(&addr6, sizeof(struct sockaddr_in6));
			msg_header->msg_namelen = sizeof(addr6);
		}

		msg_header->msg_iov = msg_iov;
		msg_header->msg_iovlen = 1;
		msg_header->msg_control = NULL;
		msg_header->msg_controllen = 0;
		msg_header->msg_flags = 0;
	}

	InitAsyncSocket(s);

	UINT64 this_thread_loop_counts = 0;

	while (true)
	{
		if (st->rand_flag && is_ipv6 == false)
		{
			for (i = 0;i < count;i++)
			{
				UINT tmp = dst_rand_addr++;
				struct msghdr* msg_header;
				msg_header = &msgvec[i].msg_hdr;
				struct sockaddr_in* addr = (struct sockaddr_in*)msg_header->msg_name;

				(*((UINT*)(&addr->sin_addr))) = htonl(tmp);
			}
		}

		if (false)
		{
			sendto(socket, buf, size, 0, is_ipv6 ? (struct sockaddr*)&addr6 : (struct sockaddr*)&addr, is_ipv6 ? sizeof(addr6) : sizeof(addr));

			udpbench_total_packets++;
		}
		else
		{
			int ret = sendmmsg(socket, msgvec, count, 0);

			udpbench_total_packets += (UINT64)count;
		}

		this_thread_loop_counts++;

		if (udpbench_num_packets_per_wait != 0)
		{
			if ((this_thread_loop_counts % (UINT64)udpbench_num_packets_per_wait) == 0)
			{
				SleepThread(udpbench_sleep_interval);
			}
		}
	}
#endif	// UNIX_LINUX
}

bool ping_test_single_try(UINT task_id, char *hostname, bool *timed_out)
{
	static bool _dummy1 = false;
	IP ip = CLEAN;

	if (timed_out == NULL)
	{
		timed_out = &_dummy1;
	}

	IP ip4 = CLEAN;
	IP ip6 = CLEAN;

	if (GetIP46Ex(&ip4, &ip6, hostname, 0, NULL) == false)
	{
		Print("Task %u: Hostname '%s' not found.\n", task_id, hostname);
		return false;
	}

	if (IsZeroIP(&ip6) == false)
	{
		CopyIP(&ip, &ip6);
	}
	else
	{
		CopyIP(&ip, &ip4);
	}

	if (IsZeroIP(&ip))
	{
		Print("Task %u: Hostname '%s' not found.\n", task_id, hostname);
		return false;
	}

	UCHAR data[64] = CLEAN;

	Rand(data, sizeof(data));

	bool ret = false;

	ICMP_RESULT *result = IcmpEchoSendBySocket(&ip, 0, data, sizeof(data), 1000);
	if (result == NULL)
	{
		Print("Task %u: IcmpEchoSend to %r (%s) error.\n", task_id, &ip, hostname);
		return false;
	}

	if (result->Timeout)
	{
		Print("Task %u: IcmpEchoSend to %r (%s): Timed out.\n", task_id, &ip, hostname);
		*timed_out = true;
	}
	else if (result->Ok == false)
	{
		Print("Task %u: IcmpEchoSend to %r (%s): Returned error.\n", task_id, &ip, hostname);
	}
	else
	{
		Print("Task %u: IcmpEchoSend to %r (%s): Ok.\n", task_id, &ip, hostname);
		ret = true;
	}

	IcmpApiFreeResult(result);

	return ret;
}



typedef struct PING_TEST_THREAD_PARAM
{
	UINT task_id;
	char target_hostname[MAX_PATH];
	LOCK *LastTickLock;
	UINT64 *LastTick;
} PING_TEST_THREAD_PARAM;

void ping_test_thread(THREAD *thread, void *param)
{
	PING_TEST_THREAD_PARAM *p = (PING_TEST_THREAD_PARAM *)param;

	while (true)
	{
		bool timed_out = false;

		UINT64 start_tick = Tick64();

		bool ok = ping_test_single_try(p->task_id, p->target_hostname, &timed_out);

		UINT64 end_tick = Tick64();

		if (ok)
		{
			Lock(p->LastTickLock);
			{
				*p->LastTick = MAX(*p->LastTick, end_tick);
			}
			Unlock(p->LastTickLock);
		}

		UINT64 spent_time = 0;
		if (end_tick > start_tick)
		{
			spent_time = end_tick - start_tick;
		}

		if (spent_time < 1000ULL)
		{
			UINT sleep_time = (UINT)(1000ULL - spent_time);

			SleepThread(sleep_time);
		}
	}
}

void ping_test(UINT num, char **arg)
{
	if (num <= 1)
	{
		Print("Usage: ping_test <timeout_secs> <target> [target2] [target3]...\n");
		return;
	}

	UINT timeout_secs = ToInt(arg[0]);

	if (timeout_secs <= 3) timeout_secs = 3;

	UINT64 timeout_msecs = (UINT64)timeout_secs * 1000ULL;

	bool ok = false;

	LIST *thread_list = NewList(NULL);

	UINT j;

	UINT64 lasttick = Tick64();
	LOCK *lasttick_lock = NewLock();

	for (j = 1;j < num;j++)
	{
		char *target_hostname = arg[j];

		PING_TEST_THREAD_PARAM *p = ZeroMalloc(sizeof(PING_TEST_THREAD_PARAM));

		p->LastTickLock = lasttick_lock;
		p->LastTick = &lasttick;
		StrCpy(p->target_hostname, sizeof(p->target_hostname), target_hostname);
		p->task_id = j;

		THREAD *t = NewThread(ping_test_thread, p);

		Add(thread_list, t);
	}

	while (true)
	{
		UINT64 now = Tick64();

		if ((lasttick + timeout_msecs) < now)
		{
			Print("Timeout occured.\n");
			_exit(-1);
		}

		SleepThread(GenRandInterval2(1000, 0));
	}
}

void udpbench_test(UINT num, char** arg)
{
	char target_hostname[MAX_SIZE];
	UINT target_port_start = 0;
	UINT target_port_end = 0;
	UINT size = 0;
	IP ip;
	UINT i, num_ports;
	bool rand_flag = false;
	LIST* ip_list = NULL;

#ifndef	UNIX_LINUX
	Print("Not supported on non-Linux OS.\n");
	return;
#endif	// UNIX_LINUX

	UINT num_cpu = GetNumberOfCpu();

	Zero(target_hostname, sizeof(target_hostname));

	if (num >= 1)
	{
		StrCpy(target_hostname, sizeof(target_hostname), arg[0]);
	}

	if (num >= 2)
	{
		char* ports = arg[1];
		TOKEN_LIST* token = ParseToken(ports, ",:");
		target_port_start = target_port_end = ToInt(arg[1]);

		if (token->NumTokens >= 2)
		{
			target_port_start = ToInt(token->Token[0]);
			target_port_end = ToInt(token->Token[1]);

			target_port_end = MAX(target_port_end, target_port_start);
		}

		FreeToken(token);
	}

	if (num >= 3)
	{
		size = ToInt(arg[2]);
	}

	if (num >= 4)
	{
		rand_flag = ToBool(arg[3]);
	}

	if (num >= 5)
	{
		UINT i;
		for (i = 4;i < num;i++)
		{
			char* ips = arg[i];
			IP ip;

			if (InStr(ips, ".") || InStr(ips, ":"))
			{
				if (GetIP(&ip, ips) || GetIPEx(&ip, ips, true))
				{
					if (ip_list == NULL)
					{
						ip_list = NewList(NULL);
					}

					Add(ip_list, Clone(&ip, sizeof(IP)));
				}
			}
			else
			{
				break;
			}
		}
	}

	if (num >= 6)
	{
		if (EndWith(arg[5], "kpps"))
		{
			udpbench_target_pps = ToInt(arg[5]) * 1000;
		}
	}
	else
	{
		udpbench_target_pps = 0;
	}

	if (num >= 7)
	{
		num_cpu = ToInt(arg[6]);
		num_cpu = MAX(num_cpu, 1);
		num_cpu = MIN(num_cpu, 64);
	}

	udpbench_total_packets = 0;

	if (IsEmptyStr(target_hostname) || target_port_start == 0 || size == 0)
	{
		Print("Usage: udpbench <hostname> <port>|<port_start:port_end> <packet_size> [dest_ip_rand_flag] [dest_ip_list] [123kpps]\n");
		Print("       If packet_size = 36 then send dns query sample packet\n");
		return;
	}

	if (GetIP(&ip, target_hostname) == false)
	{
		if (GetIPEx(&ip, target_hostname, true) == false)
		{
			Print("GetIP for %s failed.\n", target_hostname);
			return;
		}
	}

	if (ip_list != NULL)
	{
		Add(ip_list, Clone(&ip, sizeof(IP)));
	}

	if (ip_list == NULL)
	{
		Print("Target = %r\n", &ip);
	}
	else
	{
		UINT i;
		Print("Targets List = ");
		for (i = 0;i < LIST_NUM(ip_list);i++)
		{
			IP* ip = LIST_DATA(ip_list, i);

			Print("%r ", ip);
		}
		Print("\n");
	}

	if (num_cpu == 0) num_cpu = 1;
	if (num_cpu >= 64) num_cpu = 64;

	Print("Number of CPUs: %u\n", num_cpu);
	Print("Target PPS: %u\n", udpbench_target_pps);

	num_ports = target_port_end - target_port_start + 1;

	UINT index = 0;

	for (i = 0;i < num_ports;i++)
	{
		UDPBST* st;

		st = ZeroMalloc(sizeof(UDPBST));

		if (ip_list == NULL)
		{
			Copy(&st->ip, &ip, sizeof(IP));
		}
		else
		{
			Copy(&st->ip, LIST_DATA(ip_list, i % LIST_NUM(ip_list)), sizeof(IP));
		}

		st->port = target_port_start + i;
		st->size = size;
		st->rand_flag = rand_flag;

		UINT j;

		for (j = 0;j < num_cpu;j++)
		{
			Print("Thread %u: [%r]:%u\n", index++, &st->ip, st->port);
			NewThread(udpbench_thread, st);
		}
	}

	UINT64 last_tick = TickHighres64();
	UINT64 last_pcount = udpbench_total_packets;
	udpbench_sleep_interval = 10;

	if (udpbench_target_pps != 0)
	{
		udpbench_num_packets_per_wait = 32;
	}

	while (true)
	{
		SleepThread(100);

		UINT64 current_pcount = udpbench_total_packets;
		UINT64 now = TickHighres64();
		UINT64 interval = now - last_tick;

		UINT64 current_pps = (current_pcount - last_pcount) * 1000ULL / interval;
		//Print("Current PPS: %I64u kpps\n", current_pps / 1000);
		if (udpbench_num_packets_per_wait != 0)
		{
			UINT new_value = udpbench_num_packets_per_wait;

			if (current_pps > udpbench_target_pps)
			{
				new_value /= 2;
				if (new_value == 0) new_value = 1;
			}
			else
			{
				new_value++;
			}

			udpbench_num_packets_per_wait = new_value;

			UINT new_value2 = udpbench_sleep_interval;

			if (current_pps > udpbench_target_pps)
			{
				new_value2 += 20;
			}
			else
			{
				new_value2 -= 10;
			}

			if (new_value2 < 10)
			{
				new_value2 = 10;
			}

			udpbench_sleep_interval = new_value2;

			//Print("new_value = %u   new_value2 = %u\n", new_value, new_value2);
		}

		last_tick = now;
		last_pcount = current_pcount;
	}
}

void udprand_test(UINT num, char** arg)
{
	if (num < 2)
	{
		Print("Usage: udprand <dest_ip> <dest_port>\n");
		Print("Warning: Please use this command with great caution.\n");
		Print("         This command may affect network or host computer.\n\n");
		return;
	}

	char* dest_host = arg[0];
	UINT dest_port = ToInt(arg[1]);

	IP dest_ip = CLEAN;
	if (GetIP(&dest_ip, dest_host) == false)
	{
		Print("Failed to get the IP address of '%s'.\n", dest_host);
		return;
	}

	SOCK* s = NewUDP(0);

	Print("Target host: %r:%u\n", &dest_ip, dest_port);
	Print("Local port: %u\n", s->LocalPort);

	UINT i;
	for (i = 0;;i++)
	{
		UCHAR rand[64] = CLEAN;
		Rand(rand, sizeof(rand));

		SendTo(s, &dest_ip, dest_port, rand, sizeof(rand));

		if ((i % 3000) == 0)
		{
			//SleepThread(10);
		}
	}
}

void vdi_admin_main(UINT count)
{
#ifdef OS_WIN32
	DS_WIN32_RDP_POLICY pol = CLEAN;

	pol.HasValidValue = true;

	bool is_rdp_disabled = false;

	UINT rdp_port = DsGetRdpPortFromRegistry();

	if (rdp_port != 0)
	{
		SOCK *s = Connect("127.0.0.1", rdp_port);

		if (s != NULL)
		{
			Disconnect(s);
			ReleaseSock(s);
		}
		else
		{
			is_rdp_disabled = true;
		}
	}

	if (is_rdp_disabled)
	{
		Print("RDP seems to be disabled. Trying to enable it...\n");

		MsEnableRemoteDesktop();

		// Force enable RDP
		if (DsWin32SetRdpPolicy(&pol) == false)
		{
			Print("DsWin32SetRdpPolicy error.\n");
		}
	}
#endif // OS_WIN32
}

void vdi_admin_util(UINT num, char **arg)
{
	UINT i;

	Print("Start VDI Admin Tool\n");

	for (i = 0;;i++)
	{
		Print("Loop %u\n", i);

		vdi_admin_main(i);

		UINT wait_interval = GenRandInterval2(10000, 0);

		Print("Ok. Waiting for %u msecs...\n", wait_interval);

		SleepThread(wait_interval);
	}
}

typedef struct TCP_STRESS_TEST_CTX
{
	IP Ip;
	UINT Port;
} TCP_STRESS_TEST_CTX;

void tcp_stress_test_thread(THREAD *thread, void *param)
{
	TCP_STRESS_TEST_CTX *ctx = param;

	GpcTableSum("Threads", 1);

	while (true)
	{
		GpcTableEnter("Connecting");
		char ip_str[MAX_PATH] = CLEAN;
		IPToStr(ip_str, sizeof(ip_str), &ctx->Ip);
		SOCK *s = ConnectEx4(ip_str, ctx->Port, 0, NULL, NULL, NULL, false, false, true, NULL);
		GpcTableExit("Connecting");

		if (s == NULL)
		{
			GpcTableSum("Connect error", 1);
			SleepThread(10);
			continue;
		}

		GpcTableSum("Connected", 1);

		continue;

		GpcTableEnter("Established");

		if (s != NULL)
		{
			UCHAR c;
			Recv(s, &c, 1, 0);
			GpcTableSum("Disconnected", 1);
			Disconnect(s);
			ReleaseSock(s);
		}

		GpcTableExit("Established");
	}
}

void tcp_stress_test(UINT num, char **arg)
{
	if (num < 2)
	{
		Print("tcp_stress_test <target> <port>\n");
		return;
	}

	char hostname[MAX_PATH] = CLEAN;
	StrCpy(hostname, sizeof(hostname), arg[0]);
	UINT port = ToInt(arg[1]);

	IP ip = CLEAN;
	if (GetIP(&ip, hostname) == false)
	{
		Print("Error: hostname '%s' not found.\n", hostname);
		return;
	}

	Print("hostname '%s': IP = %r\n", hostname, &ip);

	GpcStartPrintStat(500);

	UINT i;
	for (i = 0;i < 1000;i++)
	{
		TCP_STRESS_TEST_CTX *ctx = ZeroMalloc(sizeof(TCP_STRESS_TEST_CTX));
		CopyIP(&ctx->Ip, &ip);
		ctx->Port = port;

		THREAD *t = NewThread(tcp_stress_test_thread, ctx);

		ReleaseThread(t);
	}

	//SleepThread(INFINITE);
}

void proxykeepalive(UINT num, char **arg)
{
	Print("Proxy keepalive function\n\n");

	UINT proxy_auth_error_counter = 0;

	while (true)
	{
		BUF *ini_buf = ReadDump("@proxykeepalive.txt");
		UINT interval = 0;

		if (ini_buf != NULL)
		{
			LIST *ini = ReadIni(ini_buf);

			char *proxy_host = IniStrValue(ini, "ProxyHost");
			UINT proxy_port = IniIntValue(ini, "ProxyPort");
			interval = IniIntValue(ini, "IntervalMsecs");
			char *target_url = IniStrValue(ini, "TargetUrl");
			UINT giveup_counter = IniIntValue(ini, "GiveupProxyAuthErrorCount");
			UINT flags = IniIntValue(ini, "Flags");
			char *proxy_ua = IniStrValue(ini, "ProxyUserAgent");
			char *proxy_username = IniStrValue(ini, "ProxyUsername");
			char *proxy_password = IniStrValue(ini, "ProxyPassword");

			if (IsFilledStr(proxy_host) && proxy_port != 0 && IsFilledStr(target_url))
			{
				INTERNET_SETTING setting = CLEAN;

				StrCpy(setting.ProxyHostName, sizeof(setting.ProxyHostName), proxy_host);
				setting.ProxyPort = proxy_port;
				setting.ProxyType = PROXY_HTTP;

				if (IsFilledStr(proxy_ua))
				{
					StrCpy(setting.ProxyUserAgent, sizeof(setting.ProxyUserAgent), proxy_ua);
				}

				StrCpy(setting.ProxyUsername, sizeof(setting.ProxyUsername), proxy_username);
				StrCpy(setting.ProxyPassword, sizeof(setting.ProxyPassword), proxy_password);

				URL_DATA data = CLEAN;
				ParseUrl(&data, target_url, false, NULL);

				UINT err = ERR_NO_ERROR;

				BUF *error_buf = NewBuf();

				bool is_server_error = false;

				char redirect_url[MAX_SIZE] = CLEAN;

				BUF *buf = HttpRequestEx6(&data, &setting, 0, 0, &err, false, NULL, NULL, NULL, NULL, 0,
					NULL, 10000000, NULL, NULL, NULL,
					false, false, error_buf, &is_server_error, flags, redirect_url, sizeof(redirect_url));

				if (buf == NULL)
				{
					UniPrint(L"HttpRequestEx6 error. Code = %u, ErrorStr = %s\n", err, _E(err));

					SeekBufToEnd(error_buf);
					WriteBufChar(error_buf, 0);

					//Print("Error details: %s\n", error_buf->Buf);

					//if (IsFilledStr(redirect_url))
					//{
					//	Print("redirect_url: %s\n", redirect_url);
					//}

					if (err == ERR_PROXY_AUTH_FAILED)
					{
						proxy_auth_error_counter++;
						Print("proxy_auth_error_counter = %u\n", proxy_auth_error_counter);
					}

					if (giveup_counter != 0 && proxy_auth_error_counter >= giveup_counter)
					{
						Print("proxy_auth_error_counter (%u) >= giveup_counter (%u)\n", proxy_auth_error_counter, giveup_counter);
						Print("Give up.\n");
						SleepThread(INFINITE);
					}
				}
				else
				{
					Print("Ok. Return size = %u\n", buf->Size);
				}

				FreeBuf(error_buf);

				FreeBuf(buf);
			}

			FreeIni(ini);
			FreeBuf(ini_buf);
		}

		if (interval == 0)
		{
			interval = 1000;
		}

		interval = GenRandInterval2(interval, 0);

		Print("Waiting for %u msecs...\n", interval);
		SleepThread(interval);
	}
}

void hello_test(UINT num, char **arg)
{
	Print("Hello World!\n");
	Print("Exiting...");
	
	exit(0);
}

void DuWfpTest();

void DuWfpTest2();

void DuWfpTest3();

void thproc(THREAD *t, void *param)
{
#ifdef OS_WIN32
	LIST *c = MsNewSidToUsernameCache();
	UINT i;
	for (i = 0;;i++)
	{
		LIST *o = MsGetThinFwList(c, 0, NULL, NULL, NULL, NULL);

		FreeDiffList(o);

		//char tmp[MAX_SIZE] = CLEAN;
		//IP ip = CLEAN;
		//StrToIP(&ip, "192.168.3.2");
		//GetHostNameInner(tmp, sizeof(tmp), &ip, GETHOSTNAME_USE_DNS_API);
	}
	MsFreeSidToUsernameCache(c);
#endif // OS_WIN32
}

void test(UINT num, char **arg)
{
#ifdef OS_WIN32

	if (false)
	{
		Debug("ret = %u\n", TfInstallDefaultConfig(L"@test1\\test1.txt", false, false, NULL, NULL));
		return;
	}

	if (false)
	{
		IO *io = FileOpen("C:\\Users\\yagi\\Desktop\\test\\test.txt", true);
		
		if (io == NULL)
		{
			Print("open err\n");
		}
		else
		{
			if (FileSetSize(io, 123) == false)
			{
				Print("setfilesize err\n");
			}

			FileClose(io);
		}

		return;
	}

	if (false)
	{
		char tmp[128] = CLEAN;
		UINT64 boottime = MsGetWindowsBootSystemTime();
		GetDateTimeStr64(tmp, sizeof(tmp), SystemToLocal64(boottime));
		Print("%s\n", tmp);
		Print("%I64u\n", MsGetTickCount64());
		Print("%I64u\n", (UINT64)GetTickCount());

		return;
	}

	if (false)
	{
		MS_EVENTREADER_SESSION *s = MsNewEventReaderSession();

		LIST *o = MsWatchEvents(s, L"System;Application", 100);

		UINT i;
		for (i = 0;i < LIST_NUM(o);i++)
		{
			MS_EVENTITEM *e = LIST_DATA(o, i);
			char dtstr[64] = CLEAN;
			GetDateTimeStr64(dtstr, sizeof(dtstr), SystemToLocal64(e->SystemTime64));
			UniPrint(L"%s, %I64u %u %S %s %s\\%s %s\n",
				e->EventLogName, e->Index, e->EventId, dtstr, e->ProviderName, e->DomainName, e->Username, e->Message);
		}

		FreeListMemItemsAndReleaseList(o);

		MsFreeEventReaderSession(s);
		return;
	}

	if (false)
	{
		MS_EVENTREADER_SESSION *s = MsNewEventReaderSession();

		while (true)
		{
			LIST *o = MsReadEvents(s, L"Application", 100);

			//UINT i;
			//for (i = 0;i < LIST_NUM(o);i++)
			//{
			//	MS_EVENTITEM *e = LIST_DATA(o, i);
			//	char dtstr[64] = CLEAN;
			//	GetDateTimeStr64(dtstr, sizeof(dtstr), SystemToLocal64(e->SystemTime64));
			//	UniPrint(L"%I64u %u %S %s %s\\%s %s\n",
			//		e->Index, e->EventId, dtstr, e->ProviderName, e->DomainName, e->Username, e->Message);
			//}

			FreeListMemItemsAndReleaseList(o);

			//Print("%u %u\n", LIST_NUM(s->MsSidCache), LIST_NUM(s->ProviderMetadataCache));

			SleepThread(100);
		}
		MsFreeEventReaderSession(s);
		return;
	}

	while (false)
	{
		//MsWtsTest1();
		MS_WTS_LOCK_STATE_RET_EX ex = CLEAN;
		MsWtsOneOrMoreUnlockedSessionExists(&ex);
		char tmp[MAX_PATH] = CLEAN;
//		GetDateTimeStr64(tmp, sizeof(tmp), SystemToLocal64(ex.LastInputTime));
		Print("%s\n", tmp);
		SleepThread(500);
	}

	if (false)
	{
		wchar_t tmp[MAX_PATH] = CLEAN;

		MsConvertDosDevicePathToFullPath(tmp, sizeof(tmp), L"\\device\\harddiskvolume4\\windows\\syswow64\\ipconfig.exe");
		//MsConvertDosDevicePathToFullPath(tmp, sizeof(tmp), L"\\device\\harddiskvolume4\\program files (x86)\\google\\chrome\\application\\chrome.exe");
		//MsConvertDosDevicePathToFullPath(tmp, sizeof(tmp), L"\\\\?\\HarddiskVolume4\\Windows\\");

		UniPrint(L"%s\n", tmp);
		return;
	}

	if (false)
	{
		char *tenuki_secret_str = "SampleConfig:Himitsu:SupamuNiZettaiTsukauna!!TsukawaretaraHaishiSuruzo!!OnegaiDesukaraSupamuNiTsukkawanaideKudasai!!Sushi_Kudasai!!By_Daiyuu_Nobori_2023/05/10";

		UCHAR sha1[SHA1_SIZE];
		HashSha1(sha1, tenuki_secret_str, StrLen(tenuki_secret_str));
		char tmp[MAX_PATH];
		BinToStr(tmp, sizeof(tmp), sha1, sizeof(sha1));
		StrLower(tmp);
		tmp[32] = 0;
		Print("%s\n", tmp);

		return;
	}

	if (false)
	{
		UINT a, b, c, d;
		MsGetFileVersionW(L"c:\\windows\\System32\\ntoskrnl.exe", &a, &b, &c, &d);
		return;
	}

	if (false)
	{
		UINT i;
		LIST *o = NewThreadList();
		for (i = 0;i < 32;i++)
		{
			THREAD *t = NewThread(thproc, NULL);
			AddThreadToThreadList(o, t);
			ReleaseThread(t);
		}

		FreeThreadList(o);

		//SleepThread(INFINITE);

		return;
	}

	if (false)
	{
		LIST *a = MsGetCurrentDnsServersList();
		while (true)
		{

			UINT i;
			for (i = 0;i < LIST_NUM(a);i++)
			{
				IP *ip = LIST_DATA(a, i);

				Print("%r\n", ip);
			}

		}
		ReleaseStrList(a);

		return;
	}

	if (false)
	{
		char tmp[64] = CLEAN;
		while (true)
		{
			Print(">");
			GetLine(tmp, sizeof(tmp));

			IP ip = CLEAN;
			StrToIP(&ip, tmp);

			char tmp2[128] = CLEAN;

			GetHostNameEx(tmp2, sizeof(tmp2), &ip, 0, GETHOSTNAME_USE_DNS_API);

			//GetNetBiosName(tmp2, sizeof(tmp2), &ip);

			//IPAddressToPtrFqdn(tmp2, sizeof(tmp2), &ip);

			Print("%s\n", tmp2);
		}
		return;
	}

	if (false)
	{
		LIST *sid_cache = MsNewSidToUsernameCache();
		LIST *o = MsGetThinFwList(sid_cache, MS_GET_THINFW_LIST_FLAGS_NO_LOCALHOST_RDP, NULL, NULL, NULL, NULL);
		FreeDiffList(o);
		MsFreeSidToUsernameCache(sid_cache);
	}
	else if (true)
	{
		wchar_t tmp[MAX_PATH] = CLEAN;
		CombinePathW(tmp, sizeof(tmp), MsGetExeDirNameW(), L"fwtest.txt");

		TF_STARTUP_SETTINGS settings = CLEAN;

		settings.Mode = TF_SVC_MODE_USERNAME;
		UniStrCpy(settings.SettingFileName, sizeof(settings.SettingFileName), tmp);

		TF_SERVICE *svc = TfStartService(&settings);

		Print("QUIT: ");

		GetLine(NULL, 0);

		TfStopService(svc);
	}
	else if (true)
	{
		LIST *o = MsGetProcessListNt(MS_GET_PROCESS_LIST_FLAG_GET_COMMAND_LINE | MS_GET_PROCESS_LIST_FLAG_GET_SID);

		LIST *cache = MsNewSidToUsernameCache();

		UINT i;
		for (i = 0;i < LIST_NUM(o);i++)
		{
			MS_PROCESS *p = LIST_DATA(o, i);

			MS_SID_INFO *sid = MsGetUsernameFromSid(cache, p->SidData, p->SidSize);

			wchar_t *un = sid == NULL ? L"(null)" : sid->Username;
			wchar_t *dm = sid == NULL ? L"(null)" : sid->DomainName;

			UniPrint(L"%u %s %u %s\\%s %u\n", p->ProcessId, p->ExeFilenameW, p->SidSize, dm, un, p->SessionId);

		}

		MsFreeProcessList(o);

		MsFreeSidToUsernameCache(cache);
	}
	else if (true)
	{
		DuWfpTest2();
	}
	else
	{
	}
#endif // OS_WIN32

}

// テスト関数一覧定義
typedef void (TEST_PROC)(UINT num, char **arg);

typedef struct TEST_LIST
{
	char *command_str;
	TEST_PROC *proc;
} TEST_LIST;

TEST_LIST test_list[] =
{
	{"test", test},
	{"udpbench", udpbench_test},
	{"udprand", udprand_test},

	{"sslserverbench", sslserverbench_test},
	{"ssb", sslserverbench_test},

	{"sslclientbench", sslclientbench_test},
	{"scb", sslclientbench_test},

	{"hello", hello_test},
	{"vdi", vdi_admin_util},
	{"proxykeepalive", proxykeepalive},
	{"heavy", heavy_test},
	{"tcp_stress_test", tcp_stress_test},

	{"ping_test", ping_test},
};

// テスト関数
void TestMain(char *cmd)
{
	char tmp[MAX_SIZE];
	bool first = true;
	bool exit_now = false;

	Print("Hamster Tester\n");
	//OSSetHighPriority();

	while (true)
	{
		Print("TEST>");
		if (first && StrLen(cmd) != 0 && g_memcheck == false)
		{
			first = false;
			StrCpy(tmp, sizeof(tmp), cmd);
			exit_now = true;
			Print("%s\n", cmd);
		}
		else
		{
#ifdef	VISTA_HAM
			_exit(0);
#endif
			if (GetLine(tmp, sizeof(tmp)) == false)
			{
				StrCpy(tmp, sizeof(tmp), "q");
			}
		}
		Trim(tmp);
		if (StrLen(tmp) != 0)
		{
			UINT i, num;
			bool b = false;
			TOKEN_LIST *token = ParseCmdLine(tmp);
			char *cmd = token->Token[0];
#ifdef	VISTA_HAM
			if (EndWith(cmd, "vlan") == false)
			{
				_exit(0);
			}
#endif
			if (!StrCmpi(cmd, "exit") || !StrCmpi(cmd, "quit") || !StrCmpi(cmd, "q"))
			{
				FreeToken(token);
				break;
			}
			else
			{
				num = sizeof(test_list) / sizeof(TEST_LIST);
				for (i = 0;i < num;i++)
				{
					if (!StrCmpi(test_list[i].command_str, cmd))
					{
						char **arg = Malloc(sizeof(char *) * (token->NumTokens - 1));
						UINT j;
						for (j = 0;j < token->NumTokens - 1;j++)
						{
							arg[j] = CopyStr(token->Token[j + 1]);
						}
						test_list[i].proc(token->NumTokens - 1, arg);
						for (j = 0;j < token->NumTokens - 1;j++)
						{
							Free(arg[j]);
						}
						Free(arg);
						b = true;
						Print("\n");
						break;
					}
				}
				if (b == false)
				{
					Print("Invalid Command: %s\n\n", cmd);
				}
			}
			FreeToken(token);

			if (exit_now)
			{
				break;
			}
		}
	}
	Print("Exiting...\n\n");
}


// main 関数
int main(int argc, char *argv[])
{
	bool memchk = false;
	UINT i;
	char cmd[MAX_SIZE];
	char *s;

	Vars_ApplyActivePatch();

	InitProcessCallOnceEx(true);

	printf("IPA-DN-ThinLib-NativeUtilApp Program.\n");

	cmd[0] = 0;
	if (argc >= 2)
	{
		for (i = 1;i < (UINT)argc;i++)
		{
			s = argv[i];
			if (s[0] == '/')
			{
				if (!StrCmpi(s, "/memcheck"))
				{
					memchk = true;
				}
			}
			else
			{
				StrCpy(cmd, sizeof(cmd), &s[0]);
			}
		}
	}

	DcSetDebugFlag(true);

	InitMayaqua(memchk, true, argc, argv);
	InitCedar();

	TestMain(cmdline);
	FreeCedar();
	FreeMayaqua();

	return 0;
}

