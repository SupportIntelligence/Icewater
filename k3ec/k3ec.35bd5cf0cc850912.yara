import "hash"

rule k3ec_35bd5cf0cc850912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.35bd5cf0cc850912"
     cluster="k3ec.35bd5cf0cc850912"
     cluster_size="7 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="malicious engine heuristic"
     md5_hashes="['1069cab7525731b0dcd965c6816f63b0', 'c3bd5300d65ac26f414abdc545c70906', '5593b6da3000020e11545119cb333151']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(35328,1536) == "999736f3764b622e493be268181ce18c"
}

