import "hash"

rule k3e9_6b64d34b9b0b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34b9b0b5912"
     cluster="k3e9.6b64d34b9b0b5912"
     cluster_size="22 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['b44e835a962b75f19995c964c35cd676', 'aa5044f4d702742554a10098de68b141', 'ab36437f76b7dcf9f11899583f4a2b69']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(1792,256) == "e968e938e7851d6777e2e0a561e83aca"
}

