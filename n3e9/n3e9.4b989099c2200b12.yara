import "hash"

rule n3e9_4b989099c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4b989099c2200b12"
     cluster="n3e9.4b989099c2200b12"
     cluster_size="21076 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="vbkrypt bxdp naprat"
     md5_hashes="['063cf67f180f0d06789494d5f26f7394', '004c4a9e68aea3b193fed139ffa2d973', '02dd1a6d8cbcef007c63f30b3e9ce4f9']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(453632,1024) == "7f7ba7ea942fc0cd6c7589538ffec4c7"
}

