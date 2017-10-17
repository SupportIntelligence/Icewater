import "hash"

rule k3e9_332ea84bc6220912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.332ea84bc6220912"
     cluster="k3e9.332ea84bc6220912"
     cluster_size="7 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob malicious"
     md5_hashes="['84903dc258bd2b995f37125f01eac16d', '84903dc258bd2b995f37125f01eac16d', '7aa3ba4fb768232ebd27ff43b10108f8']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(1024,1024) == "bafdc1c966710908612de8a0df7c0810"
}

