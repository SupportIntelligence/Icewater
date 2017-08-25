import "hash"

rule k3e9_2b1cf3e9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2b1cf3e9c8000b12"
     cluster="k3e9.2b1cf3e9c8000b12"
     cluster_size="451 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="razy backdoor simbot"
     md5_hashes="['a9e20b4c91e3d6e7e47c1d2b6f1c7098', '6e9cc49aeee3f4e5c39f35bf49aa0147', 'a6a74315deae5a4be3d61fc5b1800552']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(25600,1536) == "b5ed7b029bc65184d8f3a398fb854e6d"
}

