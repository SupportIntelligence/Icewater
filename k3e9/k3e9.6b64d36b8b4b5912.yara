import "hash"

rule k3e9_6b64d36b8b4b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d36b8b4b5912"
     cluster="k3e9.6b64d36b8b4b5912"
     cluster_size="58 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['cea78aeb684dbfa8c62fdd01cd5f1f32', '18d45393976dcbb3a7f5f3c517a8752f', 'cca521b851071ccf36a1663207a6e2bf']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(17576,1036) == "c9de54f1454eda93417385069e74c982"
}

