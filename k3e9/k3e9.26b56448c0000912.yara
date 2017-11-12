import "hash"

rule k3e9_26b56448c0000912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.26b56448c0000912"
     cluster="k3e9.26b56448c0000912"
     cluster_size="137 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="generickd waski trojandownloader"
     md5_hashes="['ab5fbdd8b4e84012860d56348d645804', '973fe26eeaff25fff49a7a7c2f4ea88d', 'cb9e7c9f4bae725223b4f96f48a50c88']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(7168,1536) == "7a0ed7188c40159367e84d9da1f60b0e"
}

