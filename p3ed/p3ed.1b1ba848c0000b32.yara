import "hash"

rule p3ed_1b1ba848c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=p3ed.1b1ba848c0000b32"
     cluster="p3ed.1b1ba848c0000b32"
     cluster_size="5 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ransom wanna exploit"
     md5_hashes="['0dd7751f6ef342e3b6565f9751b6c19d', '6e0a659e2a9dd0ffe2300d02360331e7', '6e0a659e2a9dd0ffe2300d02360331e7']"


   condition:
      filesize > 4194304 and filesize < 16777216
      and hash.md5(4096,1024) == "96805fafcac9dc0b8a60e5df785ff2e4"
}

