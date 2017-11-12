import "hash"

rule k3e9_5296b699c6200b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.5296b699c6200b14"
     cluster="k3e9.5296b699c6200b14"
     cluster_size="3 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['021c0ad74120d3499331fcd8fcbcc657', '56c48fc01c5b7d95148f6d9ecf507bd2', '021c0ad74120d3499331fcd8fcbcc657']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(1024,1024) == "eb80058900d487bd112d18ba2a5781d1"
}

