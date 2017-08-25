import "hash"

rule k3e9_2b15f3e9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2b15f3e9c8000b12"
     cluster="k3e9.2b15f3e9c8000b12"
     cluster_size="48 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="razy backdoor simbot"
     md5_hashes="['09d9b27f80617b75135853c7f48201b6', '23dcff46b29550d52b503bc24eafe2c9', 'e0e96fcca11e77ae736d677511a4cd85']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(25600,1536) == "b5ed7b029bc65184d8f3a398fb854e6d"
}

