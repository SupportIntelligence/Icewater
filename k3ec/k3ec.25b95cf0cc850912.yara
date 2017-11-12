import "hash"

rule k3ec_25b95cf0cc850912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.25b95cf0cc850912"
     cluster="k3ec.25b95cf0cc850912"
     cluster_size="3 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="malicious engine heuristic"
     md5_hashes="['446992b3116444b5d4097347f5acb7a0', 'db5076b6ef9a51d2747614b949e90a30', 'db5076b6ef9a51d2747614b949e90a30']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(35328,1536) == "999736f3764b622e493be268181ce18c"
}

