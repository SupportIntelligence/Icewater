import "hash"

rule k3e9_291bf3a9c8000b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.291bf3a9c8000b16"
     cluster="k3e9.291bf3a9c8000b16"
     cluster_size="8 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171017"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="razy backdoor injector"
     md5_hashes="['6a1e67f3fb5e914b91213d01ed4993d6', 'cef336bb742c7eaafdceb61010f634d9', 'a1ae0539c82f20d6751f3eab355c1690']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536
      and hash.md5(26112,1536) == "b5ed7b029bc65184d8f3a398fb854e6d"
}

