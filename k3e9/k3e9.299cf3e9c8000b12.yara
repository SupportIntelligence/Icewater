import "hash"

rule k3e9_299cf3e9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.299cf3e9c8000b12"
     cluster="k3e9.299cf3e9c8000b12"
     cluster_size="102 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="razy backdoor simbot"
     md5_hashes="['ee620cae439d4e1ed1f0f5dd57e44e53', 'ea6f9d5d2ef2b7e47379dd5a2fe2d1ec', 'a89c963e7650dcd907bd1414ef83a8b6']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(25600,1536) == "b5ed7b029bc65184d8f3a398fb854e6d"
}

