/*
 * One implementation of l3/api/SCapiL2.c (IMPL) with its functions renamed
 * PREFIX_*, for tests/unit/discover_test.c.
 */
#define CAT(a, b) CAT2(a, b)
#define CAT2(a, b) a##b
#define sn1SCDiscoverL2         CAT(PREFIX, _DiscoverL2)
#define sn1SCDiscoverL2Start    CAT(PREFIX, _DiscoverL2Start)
#define sn1SCDiscoverL2Response CAT(PREFIX, _DiscoverL2Response)
#define sn1SCDiscoverL2Done     CAT(PREFIX, _DiscoverL2Done)
#define find_l2_slot            CAT(PREFIX, _find_l2_slot)
#include IMPL

/* (also sets the module's list of local addresses, as a discovery on all
 * interfaces would) */
char **CAT(PREFIX, _find_interfaces)(uint32 **addrlist_ptr)
{
  char **names = find_interfaces(&addrlist);

  *addrlist_ptr = addrlist;
  return names;
}
