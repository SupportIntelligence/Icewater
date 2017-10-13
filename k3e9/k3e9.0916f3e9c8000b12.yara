import "hash"

rule k3e9_0916f3e9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.0916f3e9c8000b12"
     cluster="k3e9.0916f3e9c8000b12"
     cluster_size="145 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="razy backdoor simbot"
     md5_hashes="['d8c143dc8e4cc47ee1c5e08365f9d547', 'a0f44d624700a349a720f28cb3208f1f', 'cc6d7c9e61391c9407db77af8605dab4']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(25600,1536) == "b5ed7b029bc65184d8f3a398fb854e6d"
}

