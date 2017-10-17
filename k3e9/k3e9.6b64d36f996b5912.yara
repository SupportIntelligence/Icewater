import "hash"

rule k3e9_6b64d36f996b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d36f996b5912"
     cluster="k3e9.6b64d36f996b5912"
     cluster_size="200 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['6615a0a97f5a195d88469733ed4782cc', 'c2828290264cccf2083b3c49db590c87', '552f561cdb72eb72e945f04aa9f2e1f3']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(8252,1036) == "bf35bc45826b9aa0cee18bd0fde1c00c"
}

