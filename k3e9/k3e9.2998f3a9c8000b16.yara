import "hash"

rule k3e9_2998f3a9c8000b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2998f3a9c8000b16"
     cluster="k3e9.2998f3a9c8000b16"
     cluster_size="12 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="razy backdoor injector"
     md5_hashes="['d48257915b0986226646f0c52cc366c2', 'cba6cb14a0e4173cf8c38f48eff9de51', 'd0b6bb76df42697da31a690c1f46ede9']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(24064,1536) == "42595f358d82ed008b0da3cc81ff353d"
}

