import "hash"

rule k3e9_6b64d34f0a6b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34f0a6b5912"
     cluster="k3e9.6b64d34f0a6b5912"
     cluster_size="59 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['cefa663c1bac57d033113a7ee235574c', 'dca94b64713d157676b608fd7330e556', 'a26fd3441c7495e7d25f4a30c44b3977']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(17576,1036) == "c9de54f1454eda93417385069e74c982"
}

