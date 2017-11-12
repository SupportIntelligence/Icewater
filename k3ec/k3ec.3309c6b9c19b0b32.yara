import "hash"

rule k3ec_3309c6b9c19b0b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.3309c6b9c19b0b32"
     cluster="k3ec.3309c6b9c19b0b32"
     cluster_size="4 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="malicious engine heuristic"
     md5_hashes="['7da00eb18fbcb4d389f69244c2e74eaf', '7da00eb18fbcb4d389f69244c2e74eaf', '1cadd44bb31aa9a247d946e3a60788db']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(42496,1536) == "95b382834abdcaec213424d936d7a6ea"
}

