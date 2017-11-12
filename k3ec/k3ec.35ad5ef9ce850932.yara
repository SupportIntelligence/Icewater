import "hash"

rule k3ec_35ad5ef9ce850932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.35ad5ef9ce850932"
     cluster="k3ec.35ad5ef9ce850932"
     cluster_size="9 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="malicious engine heuristic"
     md5_hashes="['55c299849ba1df47d34f5c146e503002', '962053312f069c350aa2f491b516fbf8', '5241b22f025c5b4c8e709942fed5a844']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(35328,1536) == "999736f3764b622e493be268181ce18c"
}

