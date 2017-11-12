import "hash"

rule k3ec_3329c6b9c1930932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.3329c6b9c1930932"
     cluster="k3ec.3329c6b9c1930932"
     cluster_size="8 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="malicious engine heuristic"
     md5_hashes="['120b6490731f66c69b15a175794534ad', '120b6490731f66c69b15a175794534ad', '18dcb9263e7372422c50c7fdb64b4110']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(42496,1536) == "95b382834abdcaec213424d936d7a6ea"
}

