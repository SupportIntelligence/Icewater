import "hash"

rule k3ed_15e76b9140000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ed.15e76b9140000932"
     cluster="k3ed.15e76b9140000932"
     cluster_size="160 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="malicious proxy heuristic"
     md5_hashes="['381f2908603e456179e0f132aeff7fb9', 'efbf8d6febb346c7e45c67915cfc5a07', '2092c0328d50bb0a6415cae5e39e268a']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(17920,1024) == "c963f892cbf765f52338f04e7c608d8b"
}

