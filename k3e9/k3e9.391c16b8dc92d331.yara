import "hash"

rule k3e9_391c16b8dc92d331
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.391c16b8dc92d331"
     cluster="k3e9.391c16b8dc92d331"
     cluster_size="12 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['a89d2cd97b24a8b4ca44f4c4e321e222', '5ba170cd9c42a0ad734b22c21b574aa9', '21ad6fcb7ebebc891406b30145854a2f']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(15992,1036) == "12a1a9f460d1b72bcfb3c8676c56c972"
}

