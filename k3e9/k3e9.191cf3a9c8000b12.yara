import "hash"

rule k3e9_191cf3a9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.191cf3a9c8000b12"
     cluster="k3e9.191cf3a9c8000b12"
     cluster_size="284 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171017"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="backdoor razy injector"
     md5_hashes="['deffabeafe59724c2c6e36dc7c9f222a', 'db9385e2b6c4c2e1f64d254ba2d699f9', '7f82a66039126ebf435eac804fa8c110']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536
      and hash.md5(26112,1536) == "b5ed7b029bc65184d8f3a398fb854e6d"
}

