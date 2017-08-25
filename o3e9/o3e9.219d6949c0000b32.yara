import "hash"

rule o3e9_219d6949c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.219d6949c0000b32"
     cluster="o3e9.219d6949c0000b32"
     cluster_size="154 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="kryptik malicious adfile"
     md5_hashes="['35d0523eb595ad4ee60a7951535a2426', 'cc52e5bfe3e6c5f686b92718833395e7', '690a59c755fd029da3006484192853f7']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(1156096,1024) == "278c0355f0bbe3b85351e4c761c06a3c"
}

