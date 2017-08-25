import "hash"

rule k3e9_6b64d36b9d6b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d36b9d6b5912"
     cluster="k3e9.6b64d36b9d6b5912"
     cluster_size="25 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['c5aef73bb8c1115db5e2660ace0484a5', 'a5dab54df0971ea0b53f3c046452b4c8', 'a568b069cea3ba6b2e660368a9f50bd2']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(12396,1036) == "647cd7f4094d87659d4644490060e83e"
}

