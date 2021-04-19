// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/module_util.h"
#include "zeek/EventRegistry.h"
#include "zeek/script_opt/CPP/RuntimeInit.h"

namespace zeek::detail {

std::vector<CPP_init_func> CPP_init_funcs;

// Calls all of the initialization hooks, in the order they were added.
void init_CPPs()
	{
	for ( auto f : CPP_init_funcs )
		f();
	}

// This is a trick used to register the presence of compiled code.
// The initialization of the static variable will make CPP_init_hook
// non-null, which the main part of Zeek uses to tell that there's
// CPP code available.
static int flag_init_CPP()
	{
	CPP_init_hook = init_CPPs;
	return 0;
	}

static int dummy = flag_init_CPP();


void register_body__CPP(CPPStmtPtr body, int priority, p_hash_type hash,
                        std::vector<std::string> events)
	{
	compiled_scripts[hash] = { std::move(body), priority, std::move(events) };
	}

void register_lambda__CPP(CPPStmtPtr body, p_hash_type hash, const char* name,
                          TypePtr t, bool has_captures)
	{
	auto ft = cast_intrusive<FuncType>(t);

	// Create the quasi-global.
	auto id = install_ID(name, GLOBAL_MODULE_NAME, true, false);
	auto func = make_intrusive<CPPLambdaFunc>(name, ft, body);
	func->SetName(name);

	auto v = make_intrusive<FuncVal>(std::move(func));
	id->SetVal(std::move(v));
	id->SetType(ft);

	// Lambdas used in initializing global functions need to
	// be registered, so that the initialization can find them.
	// We do not, however, want to register *all* lambdas, because
	// the ones that use captures cannot be used as regular
	// function bodies.
	if ( ! has_captures )
		// Note, no support for lambdas that themselves refer
		// to events.
		register_body__CPP(body, 0, hash, {});
	}

void register_scripts__CPP(p_hash_type h, void (*callback)())
	{
	ASSERT(standalone_callbacks.count(h) == 0);
	standalone_callbacks[h] = callback;
	}

void activate_bodies__CPP(const char* fn, TypePtr t,
                          std::vector<p_hash_type> hashes)
	{
	auto ft = cast_intrusive<FuncType>(t);
	auto fg = lookup_ID(fn, GLOBAL_MODULE_NAME, false, false, false);

	if ( ! fg )
		{
		fg = install_ID(fn, GLOBAL_MODULE_NAME, true, false);
		fg->SetType(ft);
		}

	auto f = fg->GetVal()->AsFunc();
	const auto& bodies = f->GetBodies();

	// Track hashes of compiled bodies already associated with f.
	std::unordered_set<p_hash_type> existing_CPP_bodies;
	for ( auto& b : bodies )
		{
		auto s = b.stmts;
		if ( s->Tag() != STMT_CPP )
			continue;

		const auto& cpp_s = cast_intrusive<CPPStmt>(s);
		existing_CPP_bodies.insert(cpp_s->GetHash());
		}

	// Events we need to register.
	std::unordered_set<std::string> events;

	if ( ft->Flavor() == FUNC_FLAVOR_EVENT )
		events.insert(fn);

	std::vector<detail::IDPtr> no_inits;	// empty initialization vector
	int num_params = ft->Params()->NumFields();

	for ( auto h : hashes )
		{
		if ( existing_CPP_bodies.count(h) > 0 )
			// We're presumably running with the original script,
			// and have already incorporated this compiled body
			// into f.
			continue;

		// Add in the new body.
		ASSERT(compiled_scripts.count(h) > 0);
		auto cs = compiled_scripts[h];

		f->AddBody(cs.body, no_inits, num_params, cs.priority);

		events.insert(cs.events.begin(), cs.events.end());
		}

	for ( const auto& e : events )
		{
		auto eh = event_registry->Register(e);
		eh->SetUsed();
		}
	}

IDPtr lookup_global__CPP(const char* g, const TypePtr& t)
	{
	auto gl = lookup_ID(g, GLOBAL_MODULE_NAME, false, false, false);

	if ( ! gl )
		{
		gl = install_ID(g, GLOBAL_MODULE_NAME, true, false);
		gl->SetType(t);
		}

	return gl;
	}

Func* lookup_bif__CPP(const char* bif)
	{
	auto b = lookup_ID(bif, GLOBAL_MODULE_NAME, false, false, false);
	return b ? b->GetVal()->AsFunc() : nullptr;
	}

FuncValPtr lookup_func__CPP(std::string name, std::vector<p_hash_type> hashes,
                            const TypePtr& t)
	{
	auto ft = cast_intrusive<FuncType>(t);

	std::vector<StmtPtr> bodies;
	std::vector<int> priorities;

	for ( auto h : hashes )
		{
		ASSERT(compiled_scripts.count(h) > 0);

		const auto& f = compiled_scripts[h];
		bodies.push_back(f.body);
		priorities.push_back(f.priority);

		// This might register the same event more than once,
		// if it's used in multiple bodies, but that's okay as
		// the semantics for Register explicitly allow it.
		for ( auto& e : f.events )
			{
			auto eh = event_registry->Register(e);
			eh->SetUsed();
			}
		}

	auto sf = make_intrusive<ScriptFunc>(std::move(name), std::move(ft),
	                                     std::move(bodies),
	                                     std::move(priorities));

	return make_intrusive<FuncVal>(std::move(sf));
	}


RecordTypePtr get_record_type__CPP(const char* record_type_name)
	{
	IDPtr existing_type;

	if ( record_type_name &&
	     (existing_type = global_scope()->Find(record_type_name)) &&
	      existing_type->GetType()->Tag() == TYPE_RECORD )
		return cast_intrusive<RecordType>(existing_type->GetType());

	return make_intrusive<RecordType>(new type_decl_list());
	}

EnumTypePtr get_enum_type__CPP(const std::string& enum_type_name)
	{
	auto existing_type = global_scope()->Find(enum_type_name);

	if ( existing_type && existing_type->GetType()->Tag() == TYPE_ENUM )
		return cast_intrusive<EnumType>(existing_type->GetType());
	else
		return make_intrusive<EnumType>(enum_type_name);
	}

EnumValPtr make_enum__CPP(TypePtr t, int i)
	{
	auto et = cast_intrusive<EnumType>(std::move(t));
	return make_intrusive<EnumVal>(et, i);
	}

} // namespace zeek::detail
