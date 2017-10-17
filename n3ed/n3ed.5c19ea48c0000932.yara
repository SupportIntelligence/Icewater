import "hash"

rule n3ed_5c19ea48c0000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.5c19ea48c0000932"
     cluster="n3ed.5c19ea48c0000932"
     cluster_size="287 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="attribute heuristic highconfidence"
     md5_hashes="['433b7a621190053f44cfd53e9183b064', '84685c3b8d1d65508dbf7aab6284e3f2', 'fa923d6943c1050876513dfa844be36e']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(264704,1024) == "4e44ed2462869679911cbe3eb7f07ef7"
}

