import "hash"

rule k3e9_6b64d34b8b4b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34b8b4b5912"
     cluster="k3e9.6b64d34b8b4b5912"
     cluster_size="569 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['27af9e81c2e67379037e51b4156c93bc', 'a0bc5548c57d8c9aea81f4d92ce35e4a', 'a8902e9181ad6c09f513375fd8c2e1f8']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(14468,1036) == "3fc9b6513c182f90d41c33f933010485"
}

