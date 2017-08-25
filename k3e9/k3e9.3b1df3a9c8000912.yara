import "hash"

rule k3e9_3b1df3a9c8000912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3b1df3a9c8000912"
     cluster="k3e9.3b1df3a9c8000912"
     cluster_size="4 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="razy backdoor injector"
     md5_hashes="['1a7f8d9fd26cfe72c3d068a7b4b1870d', 'a27a99ee52a5bacea0dd74bb6535be10', '1a7f8d9fd26cfe72c3d068a7b4b1870d']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(26112,1536) == "b5ed7b029bc65184d8f3a398fb854e6d"
}

