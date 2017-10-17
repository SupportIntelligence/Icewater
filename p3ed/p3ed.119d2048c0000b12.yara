import "hash"

rule p3ed_119d2048c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=p3ed.119d2048c0000b12"
     cluster="p3ed.119d2048c0000b12"
     cluster_size="4 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ransom wanna exploit"
     md5_hashes="['14a561b8142d1bb0fea5773beb114681', '9b55a46be208485758f1f7b6df96fa6b', '14a561b8142d1bb0fea5773beb114681']"


   condition:
      filesize > 4194304 and filesize < 16777216
      and hash.md5(4096,1024) == "96805fafcac9dc0b8a60e5df785ff2e4"
}

