import "hash"

rule n3ed_393356529da31932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.393356529da31932"
     cluster="n3ed.393356529da31932"
     cluster_size="22 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bpchjo"
     md5_hashes="['daa7baf144fda9c5360cc50cc4472c2e', 'aeedac4d92946066876f8e8ba158c5ab', 'cf32c952746a22a8cd2913dc3a077a2f']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(389206,1110) == "e04b16c59527d26daf10147149e8ca9a"
}

