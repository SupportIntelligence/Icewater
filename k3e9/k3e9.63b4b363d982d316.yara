import "hash"

rule k3e9_63b4b363d982d316
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63b4b363d982d316"
     cluster="k3e9.63b4b363d982d316"
     cluster_size="56 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['a76d17d3a122405e7def03bb66f6b7e4', 'e1e6ddc09c9f1b097bf054a34d2ab79c', 'cb566f0c6765c4b8a87bef7ad41e8997']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(26624,256) == "fe88f5030104b15926c91a52764ce5e7"
}

