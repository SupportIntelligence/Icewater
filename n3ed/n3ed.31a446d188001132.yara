import "hash"

rule n3ed_31a446d188001132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.31a446d188001132"
     cluster="n3ed.31a446d188001132"
     cluster_size="443 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['0e7937e5d91b7bb3e8296e5f5a816908', '6e982d7fcf8e749178da1804f9eb8755', 'a9d467a5566a3eaae90c36e67ea6a7b9']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(286720,1024) == "21cd1f5dd6f252371e6aa6e53f74b815"
}

