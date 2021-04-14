// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/packet_analysis/Analyzer.h"
#include "zeek/packet_analysis/Component.h"
#include "zeek/packet_analysis/protocol/ip/IPBasedAnalyzer.h"
#include "zeek/analyzer/Analyzer.h"
#include "zeek/RuleMatcher.h"

namespace zeek {

class VectorVal;
using VectorValPtr = IntrusivePtr<VectorVal>;
class RecordVal;
using RecordValPtr = IntrusivePtr<RecordVal>;

namespace packet_analysis::ICMP {

class ICMPAnalyzer final : public IP::IPBasedAnalyzer {
public:
	ICMPAnalyzer();
	~ICMPAnalyzer() override;

	bool AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) override;

	static zeek::packet_analysis::AnalyzerPtr Instantiate()
		{
		return std::make_shared<ICMPAnalyzer>();
		}

	void CreateTransportAnalyzer(Connection* conn, IP::IPBasedTransportAnalyzer*& root,
	                             analyzer::pia::PIA*& pia, bool& check_port) override;

protected:

	/**
	 * Returns the port mask for an analyzer used by IsLikelyServerPort.
	 */
	uint32_t GetServerPortMask() const override { return ICMP_PORT_MASK; }

	/**
	 * Returns the transport protocol. Used by NewConn().
	 */
	TransportProto GetTransportProto() const override { return TRANSPORT_ICMP; }

	void ContinueProcessing(Connection* c, double t, bool is_orig, int remaining,
	                        Packet* pkt) override;

private:

	void ICMP_Sent(const struct icmp* icmpp, int len, int caplen, int icmpv6,
	               const u_char* data, const IP_Hdr* ip_hdr);

	void Echo(double t, const struct icmp* icmpp, int len,
			 int caplen, const u_char*& data, const IP_Hdr* ip_hdr);
	void Redirect(double t, const struct icmp* icmpp, int len,
			 int caplen, const u_char*& data, const IP_Hdr* ip_hdr);
	void RouterAdvert(double t, const struct icmp* icmpp, int len,
			 int caplen, const u_char*& data, const IP_Hdr* ip_hdr);
	void NeighborAdvert(double t, const struct icmp* icmpp, int len,
			 int caplen, const u_char*& data, const IP_Hdr* ip_hdr);
	void NeighborSolicit(double t, const struct icmp* icmpp, int len,
			 int caplen, const u_char*& data, const IP_Hdr* ip_hdr);
	void RouterSolicit(double t, const struct icmp* icmpp, int len,
			 int caplen, const u_char*& data, const IP_Hdr* ip_hdr);

	RecordValPtr BuildInfo(const struct icmp* icmpp, int len,
	                       bool icmpv6, const IP_Hdr* ip_hdr);

	void NextICMP4(double t, const struct icmp* icmpp, int len, int caplen,
	               const u_char*& data, const IP_Hdr* ip_hdr );

	RecordValPtr ExtractICMP4Context(int len, const u_char*& data);

	void Context4(double t, const struct icmp* icmpp, int len, int caplen,
	              const u_char*& data, const IP_Hdr* ip_hdr);

	TransportProto GetContextProtocol(const IP_Hdr* ip_hdr, uint32_t* src_port,
	                                  uint32_t* dst_port);

	void NextICMP6(double t, const struct icmp* icmpp, int len, int caplen,
	               const u_char*& data, const IP_Hdr* ip_hdr );

	RecordValPtr ExtractICMP6Context(int len, const u_char*& data);

	void Context6(double t, const struct icmp* icmpp, int len, int caplen,
	              const u_char*& data, const IP_Hdr* ip_hdr);

	// RFC 4861 Neighbor Discover message options
	VectorValPtr BuildNDOptionsVal(int caplen, const u_char* data);

	void UpdateEndpointVal(const ValPtr& endp, bool is_orig);

	// Returns the counterpart type to the given type (e.g., the counterpart
	// to ICMP_ECHOREPLY is ICMP_ECHO).
	int ICMP4_counterpart(int icmp_type, int icmp_code, bool& is_one_way);
	int ICMP6_counterpart(int icmp_type, int icmp_code, bool& is_one_way);

	int type;
	int code;

	Connection* conn;
	};

class ICMPTransportAnalyzer final : public IP::IPBasedTransportAnalyzer {

public:

	ICMPTransportAnalyzer(Connection* conn) :
		IP::IPBasedTransportAnalyzer("ICMP", conn) { }

	static zeek::analyzer::Analyzer* Instantiate(Connection* conn)
		{
		return new ICMPTransportAnalyzer(conn);
		}

	void AddExtraAnalyzers(Connection* conn) override;
	void UpdateConnVal(RecordVal* conn_val) override;
	void UpdateEndpointVal(const ValPtr& endp, bool is_orig);

	void UpdateLength(bool is_orig, int len);
	void Done() override;

	void InitEndpointMatcher(const IP_Hdr* ip_hdr, int len, bool is_orig);
	void MatchEndpoint(const u_char* data, int len, bool is_orig);

private:

	detail::RuleMatcherState matcher_state;
	int request_len = -1;
	int reply_len = -1;
};

} // namespace packet_analysis::ICMP
} // namespace zeek
