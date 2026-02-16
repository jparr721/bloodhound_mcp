#!/usr/bin/python3
"""
MCP Server for BloodHound 
This server acts as an interface between an LLM and the BloodHound Server
v2.0
Trying to be more token iffecient
"""
import argparse
import json
import logging
import os
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv

# Import FastMCP
from mcp.server.fastmcp import FastMCP

# Import Bloodhound API client
from lib.bloodhound_api import BloodhoundAPI, BloodhoundAPIError, BloodhoundConnectionError

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Initialize the MCP server and Bloodhound API client
mcp = FastMCP("bloodhound_mcp")
bloodhound_api = BloodhoundAPI()

# Helper function
# eliminates repitiver error handling boilerplate that was in all of the tools.
def _handle_tool_call(info_type: str, handlers: dict, **context):
    """Dispatch a composite tool call to the appropriate handler"""
    handler = handler.get(info_type)
    if not handlers:
        valid = ", ".join(sorted(handlers.keys()))
        return json.dumps({
            "error": f"Unknown info_type '{info_type}'. Valid options: {valid}"
        })
    try:
        result = handler()
        return json.dumps({
            "info_type": info_type,
            "data": result,
            **context 
        })
    except BloodhoundConnectionError as e:
        return json.dumps({"error": f"Connection error: {str(e)}"})
    except BloodhoundAPIError as e:
        return json.dumps({"error": f"API error: (HTTP {e.status_code}) {str(e)}"})
    except Exception as e:
        logger.error(f"Error in {info_type}: {str(e)}")
    
#Create the prompts
#Slimmed down prompt with instructuons to use resources for more information
@mcp.prompt()
def bloodhound_assistant() -> str:
    return """You are a security analysis assistant for BloodHound.

    You help analyze attack paths and security relationships across:
    - Active directory (users, computers, groups, GPOs, OUs, ADCS, etc.)
    - Azure / Entra ID (Users, grous, apps, service principals, tenants)
    - Other infrastructure via OpenGraph (user definded noded types, edges, and relationships)

    BloodHound models all of these as a unified graph.
    Relationships between standard AD/Entra objects and Custom OpenGraph nodes enabled attack path
    analysis across the full environment not just Active Directory.

    ## Workflow
    1. Use domain_info(info_type="search", query="...") to find objects by name or ID
    2. Use composite tools to drill into specific objects or request all of the information about the object
    3. Use cypher_query(info_type="run") for advanced cross-domain analysis
    4. Use custom_nodes to manage OpenGraph node type configurations
    5. For Azure: prefer Cypher queries over REST API tools
    6. For OpenGraph: prompt the user for OpenGraph Schema and example queries, then use these to create cypher queries

    ## Resources
    Load these for detailed references:
    - bloodhound://cypher/examples - query examples
    - bloodhound://cypher/patterns - common cypher patterns
    - bloodhound://ad/analysis-guide - AD analysis methodology
    - bloodhound://azure/analysis-guide - Azure-specific patterns
    - bloodhound://adcs/attack-guide - ADCS attack vectors (ESC1-ESC13)
    - bloodhound://custom-nodes/opengraph-guide - OpenGraph schema design
    - bloodhound://custom-nodes/examples - Custom node implementation

    Each tool's info_type parameter controls what data is retrieved.
"""

# Create the tools
#going with composite tools to cut down on the tokens

#domain info composite tool
@mcp.tool()
def domain_info(
    info_type: str = "list",
    domain_id: str = None,
    query: str = None,
    object_type: str = None,
    limit: int = 100,
    skip: int = 0,
)-> str:
    """Query domain level data from BloodHound
    info_type options:
        list - list all domains (no domain_id needed)
        search - search objects by name/ID (needs query param, domain_id not needed)
        users - users in the domain
        groups - groups in the domain
        computers - computers in the domain
        controllers - security prinicpals with control relationships
        gpos - Group Policy Objects
        ous - Organizational unites
        dc_syncers - Principals with DCSync rights
        foreign_admins - admins from other domains
        foreign_gpo_controllers - GPO controllers from other domains
        foreign_groups - groups with cross domain members
        foreign_users - users referenced across domains
        inbound_trusts - domains that trust this domain
        outbound_trusts - domains this domain trusts
        linked_gpos - GPOs linked to domain containers
    
    Args:
        info_type: what to retrieve (default: list)
        domain_id: Domain object ID (required for most info_types)
        query: Search text (for info_type=search only)
        object_type: Filter by type - User, computer, Group, GPO, OU, Domain, AZUer, etc. (search only)
        limit: Max Results (default 100, useful in large environments)
        skip: Pagination offset (default 0)
    """
    handlers = {
        "list":                    lambda: bloodhound_api.domains.get_all(),
        "search":                  lambda: bloodhound_api.domains.search_objects(query, object_type, limit=limit, skip=skip),
        "users":                   lambda: bloodhound_api.domains.get_users(domain_id, limit=limit, skip=skip),
        "groups":                  lambda: bloodhound_api.domains.get_groups(domain_id, limit=limit, skip=skip),
        "computers":               lambda: bloodhound_api.domains.get_computers(domain_id, limit=limit, skip=skip),
        "controllers":             lambda: bloodhound_api.domains.get_controllers(domain_id, limit=limit, skip=skip),
        "gpos":                    lambda: bloodhound_api.domains.get_gpos(domain_id, limit=limit, skip=skip),
        "ous":                     lambda: bloodhound_api.domains.get_ous(domain_id, limit=limit, skip=skip),
        "dc_syncers":              lambda: bloodhound_api.domains.get_dc_syncers(domain_id, limit=limit, skip=skip),
        "foreign_admins":          lambda: bloodhound_api.domains.get_foreign_admins(domain_id, limit=limit, skip=skip),
        "foreign_gpo_controllers": lambda: bloodhound_api.domains.get_foreign_gpo_controllers(domain_id, limit=limit, skip=skip),
        "foreign_groups":          lambda: bloodhound_api.domains.get_foreign_groups(domain_id, limit=limit, skip=skip),
        "foreign_users":           lambda: bloodhound_api.domains.get_foreign_users(domain_id, limit=limit, skip=skip),
        "inbound_trusts":          lambda: bloodhound_api.domains.get_inbound_trusts(domain_id, limit=limit, skip=skip),
        "outbound_trusts":         lambda: bloodhound_api.domains.get_outbound_trusts(domain_id, limit=limit, skip=skip),
        "linked_gpos":             lambda: bloodhound_api.domains.get_linked_gpos(domain_id, limit=limit, skip=skip),
    }
    return _handle_tool_call(info_type, handlers)


#User info composite tool
@mcp.tool()
def user_info(
    user_id: str,
    info_type: str = "info",
    limit: int = 100,
    skip: int = 0,
) -> str:
    """Query user data from BloodHound
    info_type options:
        info - General user properties and attributes
        admin_rights - machine/objects this user has admin rights on
        constrained_delegation - services this use can delegate to via kerberos
        controllables - objects this use can control (WriteOwner, GenericAll, etc.)
        controllers - principals that have control over this user
        dcom_rights - machines this user can execute DCOM on
        memberships - groups this user belongs to
        ps_remote_rights - machines this user can PSRemote to
        rdp_rights - machines this user can RDP to
        sessions - machines this user has active sessions
        sql_admin_rights - SQL servers this user is admin on

    Args:
        user_id: BloodHound object ID of the user (required)
        info_type: what to retrieve (default: info)
        limit: Max Results (default 100, useful in large environments)
        skip: Pagination offset (default 0)
    """
    handlers = {
        "info":                   lambda: bloodhound_api.users.get_info(user_id),
        "admin_rights":           lambda: bloodhound_api.users.get_admin_rights(user_id, limit=limit, skip=skip),
        "constrained_delegation": lambda: bloodhound_api.users.get_constrained_delegation(user_id, limit=limit, skip=skip),
        "controllables":          lambda: bloodhound_api.users.get_controllables(user_id, limit=limit, skip=skip),
        "controllers":            lambda: bloodhound_api.users.get_controllers(user_id, limit=limit, skip=skip),
        "dcom_rights":           lambda: bloodhound_api.users.get_dcom_rights(user_id, limit=limit, skip=skip),
        "memberships":           lambda: bloodhound_api.users.get_memberships(user_id, limit=limit, skip=skip),
        "ps_remote_rights":      lambda: bloodhound_api.users.get_ps_remote_rights(user_id, limit=limit, skip=skip),
        "rdp_rights":           lambda: bloodhound_api.users.get_rdp_rights(user_id, limit=limit, skip=skip),
        "sessions":             lambda: bloodhound_api.users.get_sessions(user_id, limit=limit, skip=skip),
        "sql_admin_rights":     lambda: bloodhound_api.users.get_sql_admin_rights(user_id, limit=limit, skip=skip),
    }
    return _handle_tool_call(info_type, handlers, user_id=user_id)

#group info composite tool
@mcp.tool()
def group_info(
    group_id: str,
    info_type: str = "info",
    limit: int = 100,
    skip: int = 0,
) -> str:
    """Query group data from BloodHound.
    info_type options:
        info - general group properties and attributes
        admin_rights - machine/objects this group has admin rights on
        controllables - objects this group can control
        controllers - principals that have control over this group
        dcom_rights - machines this group can execute DCOM on
        members - users and groups that are members of this group
        memberships - groups this group belongs to (nested membership)
        ps_remote_rights - machines this group can PSRemote to
        rdp_rights - machines this group can RDP to
        sessions - machines this group has active sessions on
    args:
        group_id: BloodHound object ID of the group (required)
        info_type: what to retrieve (default: info)
        limit: Max Results (default 100, useful in large environments)
        skip: Pagination offset (default 0)
    """
    handlers = {
        "info":           lambda: bloodhound_api.groups.get_info(group_id),
        "admin_rights":   lambda: bloodhound_api.groups.get_admin_rights(group_id, limit=limit, skip=skip),
        "controllables":  lambda: bloodhound_api.groups.get_controllables(group_id, limit=limit, skip=skip),
        "controllers":    lambda: bloodhound_api.groups.get_controllers(group_id, limit=limit, skip=skip),
        "dcom_rights":   lambda: bloodhound_api.groups.get_dcom_rights(group_id, limit=limit, skip=skip),
        "members":       lambda: bloodhound_api.groups.get_members(group_id, limit=limit, skip=skip),
        "memberships":   lambda: bloodhound_api.groups.get_memberships(group_id, limit=limit, skip=skip),
        "ps_remote_rights":  lambda: bloodhound_api.groups.get_ps_remote_rights(group_id, limit=limit, skip=skip),
        "rdp_rights":     lambda: bloodhound_api.groups.get_rdp_rights(group_id, limit=limit, skip=skip),
        "sessions":       lambda: bloodhound_api.groups.get_sessions(group_id, limit=limit, skip=skip),
    }
    return _handle_tool_call(info_type, handlers, group_id=group_id)

#computer info composite tool
@mcp.tool()
def computer_info(
    computer_id: str,
    info_type: str = "info",
    limit: int = 100,
    skip: int = 0,
) -> str:
    """Query computer data from BloodHound.
    info_type options:
        info - general computer properties and attributes
        admin_rights - objects this computer has admin rights on
        admin_users - users/groups that have admin rights on this computer
        constrained_delegation - services this computer can delegate to via kerberos
        constrained_users - users with contained delegation TO this computer
        controllables - objects this computer can control
        controllers - principals that have control over this computer
        dcom_rights - machines this computer can execute DCOM on
        dcom_users - users/groups with DCOM rights ON this computer
        group_membership - groups this computer belongs to
        ps_remote_rights - machines this computer can PSRemote to
        ps_remote_users - users/groups with PSRemote rights ON this computer
        rdp_rights - machines this computer can RDP to
        rdp_users - users/groups with RDP rights ON this computer
        sessions - users with active sessions on this computer
        sql_admins - SQL servers this computer is admin on

    args:
        computer_id: BloodHound object ID of the computer (required)
        info_type: what to retrieve (default: info)
        limit: Max Results (default 100, useful in large environments)
        skip: Pagination offset (default 0)
    """
    handlers = {
        "info":                   lambda: bloodhound_api.computers.get_info(computer_id),
        "admin_rights":           lambda: bloodhound_api.computers.get_admin_rights(computer_id, limit=limit, skip=skip),
        "admin_users":            lambda: bloodhound_api.computers.get_admin_users(computer_id, limit=limit, skip=skip),
        "constrained_delegation": lambda: bloodhound_api.computers.get_constrained_delegation(computer_id, limit=limit, skip=skip),
        "constrained_users":      lambda: bloodhound_api.computers.get_constrained_users(computer_id, limit=limit, skip=skip),
        "controllables":          lambda: bloodhound_api.computers.get_controllables(computer_id, limit=limit, skip=skip),
        "controllers":            lambda: bloodhound_api.computers.get_controllers(computer_id, limit=limit, skip=skip),
        "dcom_rights":           lambda: bloodhound_api.computers.get_dcom_rights(computer_id, limit=limit, skip=skip),
        "dcom_users":            lambda: bloodhound_api.computers.get_dcom_users(computer_id, limit=limit, skip=skip),
        "group_membership":      lambda: bloodhound_api.computers.get_group_membership(computer_id, limit=limit, skip=skip),
        "ps_remote_rights":      lambda: bloodhound_api.computers.get_ps_remote_rights(computer_id, limit=limit, skip=skip),
        "ps_remote_users":       lambda: bloodhound_api.computers.get_ps_remote_users(computer_id, limit=limit, skip=skip),
        "rdp_rights":           lambda: bloodhound_api.computers.get_rdp_rights(computer_id, limit=limit, skip=skip),
        "rdp_users":            lambda: bloodhound_api.computers.get_rdp_users(computer_id, limit=limit, skip=skip),
        "sessions":             lambda: bloodhound_api.computers.get_sessions(computer_id, limit=limit, skip=skip),
        "sql_admins":           lambda: bloodhound_api.computers.get_sql_admins(computer_id, limit=limit, skip=skip),
    }
    return _handle_tool_call(info_type, handlers, computer_id=computer_id)

#Organizational Unit info composite tool
@mcp.tool()
def ou_info(
    ou_id: str,
    info_type: str = "info",
    limit: int = 100,
    skip: int = 0,
) -> str:
    """Query OU data from BloodHound.
    info_type options:
        info - general OU Properties and attributes
        computers - computers in this OU
        groups - groups in this OU
        gpos - GPOs linked to this OU
        users - users in this OU
    args:
    ou_id: BloodHound object ID of the OU (required)
    info_type: what to retrieve (default: info)
    limit: Max Results (default 100, useful in large environments)
    skip: Pagination offset (default 0)
    """
    handlers = {
        "info":      lambda: bloodhound_api.ous.get_info(ou_id),
        "computers": lambda: bloodhound_api.ous.get_computers(ou_id, limit=limit, skip=skip),
        "groups":    lambda: bloodhound_api.ous.get_groups(ou_id, limit=limit, skip=skip),
        "gpos":      lambda: bloodhound_api.ous.get_gpos(ou_id, limit=limit, skip=skip),
        "users":     lambda: bloodhound_api.ous.get_users(ou_id, limit=limit, skip=skip),
    }
    return _handle_tool_call(info_type, handlers, ou_id=ou_id)

# Group Policy Object info composite tool
@mcp.tool()
def gpo_info(
    gpo_id: str,
    info_type: str = "info",
    limit: int = 100,
    skip: int = 0,
) -> str:
    """Query GPO data from BloodHound.
    info_type options:
        info - general GPO properties and attributes
        computers - computers this GPO is applied to
        controllers - principals that can modify this GPO
        ous - OUs this GPO is linked to
        tier_zeros - tier-zero principals associated with this GPO
        users - users this GPO is applied to
    args:
        gpo_id: BloodHound object ID of the GPO (required)
        info_type: what to retrieve (default: info)
        limit: Max Results (default 100, useful in large environments)
        skip: Pagination offset (default 0)
    """
    handlers = {
        "info":      lambda: bloodhound_api.gpos.get_info(gpo_id),
        "computers": lambda: bloodhound_api.gpos.get_computers(gpo_id, limit=limit, skip=skip),
        "controllers":lambda: bloodhound_api.gpos.get_controllers(gpo_id, limit=limit, skip=skip),
        "ous":       lambda: bloodhound_api.gpos.get_ous(gpo_id, limit=limit, skip=skip),
        "tier_zeros":lambda: bloodhound_api.gpos.get_tier_zeros(gpo_id, limit=limit, skip=skip),
        "users":     lambda: bloodhound_api.gpos.get_users(gpo_id, limit=limit, skip=skip),
    }
    return _handle_tool_call(info_type, handlers, gpo_id=gpo_id)

# Graph analysis composte tool
@mcp.tool()
def graph_analysis(
    info_type: str,
    query: str = None,
    search_type: str = "fuzzy",
    start_node: str = None,
    end_node: str = None,
    source_node: str = None,
    target_node: str = None,
    edge_type: str = None,
    relationship_kinds: str = None,
)-> str:
    """Perform graph analysis operations in BloodHound
    
    info_type options:
        search - search for nodes by name (needs: queryl optional: search_type)
        shortest_path - find shortest attack path between two nodes (needs: start_node, end_node; optional relationship_kinds)
        edge_composition - decompose a complex edge into underlying relationships (needs: source_node, target_node, edge_type)
        relay_targets - find valid NTLM relay targets for a given node (needs: source_node, target_node, edge_type)

    args:
        info_type: what type of graph operation to perform (required)
        query: search text (for search)
        search_type: type of search - fuzzy (default) or exact (for search)
        start_node: Object ID of source node (for shortest_path)
        end_node: Object ID of target node (for shortest_path)
        source_node: Object ID of source node (for edge_composition and relay_targets)
        target_node: Object ID of target node (for edge_composition and relay_targets)
        edge_type: Realtionship type like "MemberOf", "AdminTo", (for edge_composition and relay_targets)
        relationship_kinds: Comma-separated relationship filter (for shortest_path, optional)
    """
    handlers = {
        "search":            lambda: bloodhound_api.cypher.search_nodes(query, search_type),
        "shortest_path":     lambda: bloodhound_api.cypher.shortest_path(start_node, end_node, relationship_kinds),
        "edge_composition":  lambda: bloodhound_api.cypher.edge_composition(source_node, target_node, edge_type),
        "relay_targets":     lambda: bloodhound_api.cypher.relay_targets(source_node, target_node, edge_type),
    }
    return _handle_tool_call(info_type, handlers, query=query, search_type=search_type, start_node=start_node, end_node=end_node, source_node=source_node, target_node=target_node, edge_type=edge_type, relationship_kinds=relationship_kinds)

# Active Directory Certificate Services composite tool
@mcp.tool()
def adcs_info(
    object_id: str,
    info_type: str,
    limit: int = 100,
    skip: int = 0,
) -> str:
    """QUery AD Certificate Services data from BloodHound
    object_id is the template_id or the ca_id depending on the info_type
    info_type options:
        cert_template_info - certificate template properties (object_id = template ID)
        cert_template_controllers - who can modify this template - key for ESC1/ESC2 (object_id = template ID)
        root_ca_info - root ca properties (object_id = CA ID)
        root_ca_controllers - who controls the root ca - key for ESC4/ESC5 (object_id = CA ID)
        enterprise_ca_info - enterprise CA properties (object_id = CA ID)
        enterprise_ca_controllers - who controls the enterprise CA - key for ESC3/ESC6 (object_id = CA ID)
        aia_ca_controllers - who controls the AIA CA (object_id = CA ID)

    args:
        object_id: Template ID or CA ID depending on info_type (required)
        info_type: what to retrieve (required)
        limit: Max Results (default 100, useful in large environments)
        skip: Pagination offset (default 0)
    """
    handlers = {
        "cert_template_info":           lambda: bloodhound_api.adcs.get_cert_template_info(object_id),
        "cert_template_controllers":    lambda: bloodhound_api.adcs.get_cert_template_controllers(object_id, limit=limit, skip=skip),
        "root_ca_info":                lambda: bloodhound_api.adcs.get_root_ca_info(object_id),
        "root_ca_controllers":         lambda: bloodhound_api.adcs.get_root_ca_controllers(object_id, limit=limit, skip=skip),
        "enterprise_ca_info":          lambda: bloodhound_api.adcs.get_enterprise_ca_info(object_id),
        "enterprise_ca_controllers":   lambda: bloodhound_api.adcs.get_enterprise_ca_controllers(object_id, limit=limit, skip=skip),
        "aia_ca_controllers":         lambda: bloodhound_api.adcs.get_aia_ca_controllers(object_id, limit=limit, skip=skip),
    }
    return _handle_tool_call(info_type, handlers, object_id=object_id)

# Cypher query composite tool
@mcp.tool()
def cypher_query(
    info_type: str,
    query: str = None,
    include_properties: bool = True,
    name: str = None,
    query_id: str = None,
    result_json: str = None,
    description: str = None,
    user_ids: str = None,
    public: bool = False,
    limit: int = 100,
    skip: int = 0,
)-> str:
    """Execute and manage Cypher queries in BloodHound.
    
    info_type options:
        run - execute a cypher query (needs: query; optional: include_properties)
        interpret - interpret a natural language query into cypher (needs: query, result_json)
        list_saved - list saved queries (optional: name, skip, limit)
        create_saved - save a new query (needs: name, query)
        get_saved - get details of a saved query (needs: query_id)
        update_saved - update an existing saved query (needs: query_id; optional: name, query, description)
        delete_saved - delete a saved query (needs: query_id)
        share_saved - share a saved query with other users (needs: query_id; optional: user_ids, public)
        validate - validate a cypher query for syntax and semantics (needs: query)

    args:
        info_type: Operation to perform
        query: Cypher query string (for run, create_saved, update_saved, validate)
        include_properties: Include node/edge properties in results (for run, default: True)
        name: Query name (for create_saved, update_saved, list_saved filter)
        query_id: Saved query ID (for get_saved, update_saved, delete_saved, share_saved)
        result_json: JSON result string from a previous run (for interpret)
        description: Query description (for update_saved)
        user_ids: Comma-separated user IDs to share with (for share_saved)
        public: Make query public (for share_saved, default: False)
        limit: Max results (default 100)
        skip: Pagination offset (default 0)
    """
    #run and interpret have special handling
    if info_type == "run":
        return _cypher_run(query, include_properties)
    elif info_type == "interpret":
        return _cypher_interpret(query, result_json)
    #standard dispatch for saved query CRUD
    handlers = {
        "list_saved": lambda: bloodhound_api.cypher.list_saved_queries(skip, limit, name),
        "create_saved": lambda: bloodhound_api.cypher.create_saved_query(name, query),
        "get_saved": lambda: bloodhound_api.cypher.get_saved_query(query_id),
        "update_saved": lambda: bloodhound_api.cypher.update_saved_query(query_id, name, query, description),
        "delete_saved": lambda: bloodhound_api.cypher.delete_saved_query(query_id),
        "share_saved": lambda: bloodhound_api.cypher.share_saved_query(
            query_id,
            [int(uid.strip()) for uid in user_ids.split(",")] if user_ids else [],
            public
        ),
        "validate": lambda: bloodhound_api.cypher.validate_query(query),
    }
    return _handle_tool_call(info_type, handlers)
def _cypher_run(query: str, include_properties: bool = True) -> str:
    """Execute a Cypher query with proper HTTP Status interpretation"""
    try:
        result = bloodhound_api.cypher.run_query(query, include_properties)
        #handle metadat enriched resposne formmat
        if isinstance(result, dict) and "metadata" in result:
            has_results = result["metadata"].get("has_result", True)
            result_data = result.get("data", result)
        else:
            result_data = resulthas_result = bool(result_data.get("nodes") or result_data.get("edges"))
        return json.dumps({
            "info_type": "run",
            "success": True,
            "has_results": has_results,
            "data": result_data,
            "node_count": len(result_data.get("nodes", [])),
            "edge_count": len(result_data.get("edges", [])),
        })
    except BloodhoundAPIError as e:
        #TODO: expand this with more specific error handling based on status codes and error messages from the BloodHound API
        #Bloodhound errors are not specific and just give you the status number, this kinda sucks for this
        error_map = {
            400: ("syntax_error", "check node labels, relationship types, and property names"),
            401: ("auth_error", "authentication failed - check credentials and permissions"),
            403: ("permission_error", "you do not have permission to run this query"),
            404: ("not_found", "the query does not have any results"),
            500: ("server_failure", "the query may have returned too much data, try using a limit"),
        }
        if e.status_code in error_map:
            etype, hint = error_map[e.status_code]
            return json.dumps({"success": False, "error_type": etype, "error":str(e), "hint": hint})
        if e.status_code > 500:
            return json.dumps({"success": False, "error_type": "server_error", "error": str(e)})
        return json.dumps({"success": False, "error":str(e)})

# This entire function may be completely unneeded. I need to do some A B testing to see if this is providing value or just add extra steps
#TODO: A B Testing with this function existing or not existing.
def _cypher_interpret(query: str, result_json: str) -> str:
    """interpret cypher results for offensive security context"""
    try:
        result = json.loads(result_json) if isinstance(result_json, str) else result_json
        if not result.get("success", False):
            return json.dumps({
                "info_type": "interpret",
                "interpretation": "Query failed - see error details in the result",
                "error": result.get("error", "Unknown")
            })
        nodes = result.get("data", {}).get("nodes", [])
        edges = result.get("data", {}).get("edges", [])
        query_lower = query.lower()

        #not sure if this is necessary going to comment it all out
        #if "domain admin" in query_lower:
        #    interpretation = f"Found {len(nodes)} Domain Admin related objects" if nodes else "No Domain Admin Relationships found"
        #elif "kerberoast" in query_lower:
        #    interpretation = f"Found {len(nodes)} Kerberoastable accounts" if nodes else "No Kerberoastable accounts found"
        #elif "shortest path" in query_lower or "all paths" in query_lower:
        #    interpretation = f"Found {len(edges)} potential attack paths between the specified nodes" if edges else "No attack paths found between the specified nodes"
        #else:
        #    interpretation = f"Query returned {len(nodes)} nodes and {len(edges)} edges. Review the results for potential security insights."
        return json.dumps({
            "info_type": "interpret",
            "nodes_found": len(nodes),
            "edges_found": len(edges),
            "has_results": len(nodes) > 0 or len(edges) > 0,
        })
    except Exception as e:
        return json.dumps({
            "info_type": "interpret",
            "interpretation": "Failed to interpret query results",
            "error": str(e)
        })

#data quality composite tool
@mcp.tool()
def data_quality(
    info_type: str = "completeness",
    domain_id: str = None,
    tenant_id: str = None,
    platform_id: str = None,
    start: str = None,
    end: str = None,
    sort_by: str = None,
    skip: int = 0,
    limit: int = 100,
)-> str:
    """Query data quality and collection statistics from BloodHound
    info_type options:
        completeness - overall database completeness stats (no params needed)
        ad_domain - collection quality over time for an AD domain (needs: domain_id)
        azure_tenant - collection quality over time for an azure tenant (needs: tenant_id)
        platform - aggregate quality stats for a platform (needs: platform_id - "ad" or "azure")

    args:
    info_type: what to retrieve (default: completeness)
    domain_id: AD domain ID
    platform_id: "ad" or "azure"
    start: Start datetime in RFC-3339 format
    end: end datetime in RFC-3339 format
    sort_by: Sort field - "created_at" or "updated_at" (optional)
    skip: Pagination offset (default 0)
    limit: max results (default 100)  
    """
    handlers = {
        "completeness": lambda: bloodhound_api.data_quality.get_completeness_stats(),
        "ad_domain":    lambda: bloodhound_api.data_quality.get_ad_domain_data_quality_stats(
            domain_id, start, end, sort_by, skip, limit
        ),
        "azure_tenant": lambda: bloodhound_api.data_quality.get_azure_tenant_data_quality_stats(
            tenant_id, start, end, sort_by, skip, limit
        ),
        "platform":     lambda: bloodhound_api.data_quality.get_platform_data_quality_stats(
            platform_id, start, end, sort_by, skip, limit
        ),
    }
    return _handle_tool_call(info_type, handlers)

# Custom OpenGraph nodes composite tool
@mcp.tool()
def custom_nodes(
    info_type: str = "list",
    kind_name: str = None,
    custom_types_json: str = None,
    config_json: str = None,
    icon_config_json: str = None,
) -> str:
    """Manage custom node type configs in BloodHound
    info_type options:
        list - list all custome node configs
        get - get details for a specific node kind (needs: kind_name)
        create - create new node kind with display metadata (needs: custom_types_json)
        update - update a node kind's display config (needs: kind_name, config_json)
        delete - delete a node kind (needs: kind_name)
        validate_icon - validate icon config before creating/updating (needs: icon_config_json)

    args:
        info_type: what to retrieve (default: list)
        kind_name: Custom node kind name (for get,update, delete)
        custom_types_json: JSON string for creating a new node kind (for create)
        config_json: JSON string for updating a node kind's display config (for update)
        icon_config_json: JSON string for validating icon config (for validate_icon)
    """
    def _create():
        types = json.loads(custom_types_json)
        for name, config in types.items():
            if "icon" in config:
                validation = bloodhound_api.custom_nodes.validate_icon_config(config["icon"])
                if not validation["valid"]:
                    return {"error": f"Invalid icon config for {name}: {validation['error']}"}
        return bloodhound_api.custom_nodes.create_custom_node_kinds(types)
    def _update():
        config = json.loads(config_json)
        if "icon" in config:
            validation = bloodhound_api.custom_nodes.validate_icon_config(config["icon"])
            if not validation["valid"]:
                return {"error": f"Invalid icon config: {validation['error']}"}
        return bloodhound_api.custom_nodes.update_custom_node_kind(kind_name, config)
    def _validate_icon():
        icon = json.loads(icon_config_json)
        return bloodhound_api.custom_nodes.validate_icon_config(icon)
    handlers = {
        "list": lambda: bloodhound_api.custom_nodes.list_custom_node_kinds(),
        "get": lambda: bloodhound_api.custom_nodes.get_custom_node_kind(kind_name),
        "create": _create,
        "update": _update,
        "delete": lambda: bloodhound_api.custom_nodes.delete_custom_node_kind(kind_name),
        "validate_icon": _validate_icon,
    }
    return _handle_tool_call(info_type, handlers)

# Asset Group composite tool
@mcp.tool()
def asset_groups(
    info_type: str = "list",
    asset_group_id: str = None,
    asst_group_tag_id: int = None,
    name: str = None,
    tag: str = None,
    sort_by: str = None,
    system_group: bool = None,
    selectors_json: str = None,
    skip: int = 0,
    limit: int = 100,
) -> str:
    """Manage Asset isolation groups and tages in BloodHound
    
    info_type options:
        list - list all asset groups (optional filters: name, tag, sort_by, system_group)
        get - get a specific asset group (requires: asset_group_id)
        create - create a new asset group (requires: name, tag)
        update - update an existing asset group (requires: asset_group_id)
        delete - delete an asset group (requires: asset_group_id)
        collections - list historical membership snapshots (requires: asset_group_id)
        member_counts - get member counts by object type (requires: asset_group_id)
        update_selectors - set auto membership selectors (requires: asset_group_id, selectors_json)
        list_tags - list asset group tags (optional: name, tag, sort_by)
        create_tag - create a new asset group tag (requires: name, tag)
        tag_members - list members of a tag (requires: asset_group_tag_id)

    args:
        info_type: operation to perform (default: list)
        asset_group_id: Asset group ID (for get, update, delete, collections, member_counts, update_selectors)
        asset_group_tag_id: Tag ID (for tag_members)
        name: Group/tag name (for create, update, create_tag, or filters)
        tag: Tag value (for create, update, create_tag, or filters)
        sort_by: Sort field (for list, list tags)
        system_group: Filter by system group (for list)
        selectors_json: JSON array of selector specs (for update_selectors)
        skip: Pagination offset (default 0)
        limit: Max results (default 100)
    """
    handlers = {
        "list":             lambda: bloodhound_api.asset_groups.list_asset_groups(
            sort_by=sort_by, name=name, tag=tag, system_group=system_group
        ),
        "get":              lambda: bloodhound_api.asset_groups.get_asset_group(asset_group_id),
        "create":           lambda: bloodhound_api.asset_groups.create_asset_group(name, tag),
        "update":           lambda: bloodhound_api.asset_groups.update_asset_group(asset_group_id, name),
        "delete":           lambda: bloodhound_api.asset_groups.delete_asset_group(asset_group_id),
        "collections":      lambda: bloodhound_api.asset_groups.list_asset_group_collections(
            asset_group_id, skip=skip, limit=limit
        ),
        "member_counts":    lambda: bloodhound_api.asset_groups.list_asset_group_member_counts(asset_group_id),
        "update_selectors": lambda: bloodhound_api.asset_groups.update_asset_group_selectors(
            asset_group_id, json.loads(selectors_json)
        ),
        "list_tags":        lambda: bloodhound_api.asset_groups.list_asset_group_tags(
            sort_by=sort_by, name=name, tag=tag, skip=skip, limit=limit
        ),
        "create_tag":       lambda: bloodhound_api.asset_groups.create_asset_group_tag(name, tag),
        "tag_members":      lambda: bloodhound_api.asset_groups.list_asset_group_tag_members(
            asset_group_tag_id, skip=skip, limit=limit
        ),
    }
    return _handle_tool_call(info_type, handlers)

    
                             








# Create the Resources for the LLM



