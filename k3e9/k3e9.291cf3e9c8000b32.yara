import "hash"

rule k3e9_291cf3e9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.291cf3e9c8000b32"
     cluster="k3e9.291cf3e9c8000b32"
     cluster_size="591 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="backdoor razy simbot"
     md5_hashes="['387a0abb7f10e149abb83add128955d7', '0a472486f595c8b99bc078f4dc913248', 'a4348b7dd1a450dbc86cf8a0ed321dec']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(25600,1536) == "b5ed7b029bc65184d8f3a398fb854e6d"
}

