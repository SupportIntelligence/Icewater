import "hash"

rule k3e9_2b1ef3e9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2b1ef3e9c8000b12"
     cluster="k3e9.2b1ef3e9c8000b12"
     cluster_size="390 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="razy backdoor simbot"
     md5_hashes="['ae62ed8029c11fa36f9b8b7457b579e1', '003b9daf0c0685d8c0cc9853d2a54ade', '684adeb50d6373dd1ee3979b83aaed43']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(25600,1536) == "b5ed7b029bc65184d8f3a398fb854e6d"
}

