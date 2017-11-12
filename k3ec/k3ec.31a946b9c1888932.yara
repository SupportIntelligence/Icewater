import "hash"

rule k3ec_31a946b9c1888932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.31a946b9c1888932"
     cluster="k3ec.31a946b9c1888932"
     cluster_size="25 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="malicious engine heuristic"
     md5_hashes="['58c1dacf04e7f3ac81e59941632581ca', 'f4c6b8e381e9519965c3d8c3028041ed', '52ed7e90f3eed1a160be0b927b602597']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(43520,1536) == "bed229a33d33f2961e0d20f51268104d"
}

