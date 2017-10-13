import "hash"

rule m3e9_6d14dee9c6400b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6d14dee9c6400b12"
     cluster="m3e9.6d14dee9c6400b12"
     cluster_size="1756 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="symmi swisyn abzf"
     md5_hashes="['21c20e52b7344341d8027409bf98b861', '2d783c015fa30dc5aa307604e269173e', '0d571e6b1283ab6d3d84a02f046093ff']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(26624,1024) == "f34865af21537c41ff5fcd9c4707274a"
}

