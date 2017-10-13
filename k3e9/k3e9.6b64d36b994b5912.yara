import "hash"

rule k3e9_6b64d36b994b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d36b994b5912"
     cluster="k3e9.6b64d36b994b5912"
     cluster_size="217 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['cceb7493ea572288372e941dd6ead473', 'b8c614a5a1bc9a02db4bebc8c43d9f18', 'fc75dd4a49f041a8a5f3bf0ce0671c64']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(3072,1036) == "a9d8654475cb556fb1cf62b83e2fa778"
}

