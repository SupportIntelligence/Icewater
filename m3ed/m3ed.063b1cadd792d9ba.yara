import "hash"

rule m3ed_063b1cadd792d9ba
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.063b1cadd792d9ba"
     cluster="m3ed.063b1cadd792d9ba"
     cluster_size="310 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="delf malicious dangerousobject"
     md5_hashes="['557d190e4c74e19f5ac5d8cb29a561d9', '1499b7a6666bf4a6142999b531ba631e', 'edb75618ded9ba5ea91617ee1bebbc8c']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(217600,1195) == "47a911c8407ae9f9a1bbca80b8445c2d"
}

