import "hash"

rule k3e9_125a9299c2200b20
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.125a9299c2200b20"
     cluster="k3e9.125a9299c2200b20"
     cluster_size="100 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171017"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['a28f9e2bc8ffde675dc3432a0a09148e', 'ef0a1fbf261fe50a5dfcda8eacd81c08', 'bb8bfcf6771f2dfbdd9436cc90aee04e']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536
      and hash.md5(9216,1024) == "5e1f5574dfff7e1b891594910b6ed454"
}

