import "hash"

rule n3e9_233672a6df2b1932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.233672a6df2b1932"
     cluster="n3e9.233672a6df2b1932"
     cluster_size="4 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="malicious fvyj heuristic"
     md5_hashes="['64ad0a9734f3a7a5b5d5e2d071547275', '64ad0a9734f3a7a5b5d5e2d071547275', '7eb400a854c49adc604756e80fac803c']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(651264,1024) == "b8148c16f5ec70421a467d6709d8b456"
}

