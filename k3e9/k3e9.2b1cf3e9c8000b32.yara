import "hash"

rule k3e9_2b1cf3e9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2b1cf3e9c8000b32"
     cluster="k3e9.2b1cf3e9c8000b32"
     cluster_size="177 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="razy backdoor simbot"
     md5_hashes="['0a05c153ea84d0a392b4e898a7fcebb0', '9fe964779fa3d94f4f58282042980b59', 'bd22e3976f7ed6767ef7b83dce3e3e7c']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(25600,1536) == "b5ed7b029bc65184d8f3a398fb854e6d"
}

