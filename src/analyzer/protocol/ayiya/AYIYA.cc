
#include "AYIYA.h"
#include "Func.h"

using namespace analyzer::ayiya;

AYIYA_Analyzer::AYIYA_Analyzer(Connection* conn)
: Analyzer("AYIYA", conn)
	{
	interp = new binpac::AYIYA::AYIYA_Conn(this);
	}

AYIYA_Analyzer::~AYIYA_Analyzer()
	{
	delete interp;
	}

void AYIYA_Analyzer::Done()
	{
	Analyzer::Done();
	Event(udp_session_done);
	}

void AYIYA_Analyzer::DeliverPacket(uint64_t len, const u_char* data, bool orig, uint64_t seq, const IP_Hdr* ip, int caplen)
	{
	Analyzer::DeliverPacket(len, data, orig, seq, ip, caplen);

	try
		{
		interp->NewData(orig, data, data + len);
		}
	catch ( const binpac::Exception& e )
		{
		ProtocolViolation(fmt("Binpac exception: %s", e.c_msg()));
		}
	}
