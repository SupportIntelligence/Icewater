import "hash"

rule k3e9_2b16f3e9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2b16f3e9c8000b32"
     cluster="k3e9.2b16f3e9c8000b32"
     cluster_size="152 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="razy backdoor simbot"
     md5_hashes="['ac0e8a3f0b293f303eb6bfd03c147e51', 'a3df92c7482dd5fd0e8a8d3b4e7858bf', 'b6c82c7e4bfc6a9b86d1a004bd29f35f']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(25600,1536) == "b5ed7b029bc65184d8f3a398fb854e6d"
}

