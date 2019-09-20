// See the file "COPYING" in the main distribution directory for copyright.

#ifndef ANALYZER_PROTOCOL_FINGER_FINGER_H
#define ANALYZER_PROTOCOL_FINGER_FINGER_H

#include "analyzer/protocol/tcp/TCP.h"
#include "analyzer/protocol/tcp/ContentLine.h"

namespace analyzer { namespace finger {

class Finger_Analyzer : public tcp::TCP_ApplicationAnalyzer {
public:
	explicit Finger_Analyzer(Connection* conn);
	~Finger_Analyzer() override {}

	void Done() override;
	// Line-based input.
	void DeliverStream(uint64_t len, const u_char* data, bool orig) override;

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new Finger_Analyzer(conn); }

protected:
	tcp::ContentLine_Analyzer* content_line_orig;
	tcp::ContentLine_Analyzer* content_line_resp;
	int did_deliver;
};

} } // namespace analyzer::* 

#endif
