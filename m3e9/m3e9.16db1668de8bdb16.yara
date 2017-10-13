import "hash"

rule m3e9_16db1668de8bdb16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.16db1668de8bdb16"
     cluster="m3e9.16db1668de8bdb16"
     cluster_size="137 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="cerber ransom zbot"
     md5_hashes="['da5bc2cd41327112278e71e43bb1b56e', 'da5bc2cd41327112278e71e43bb1b56e', '0b4483fb3a321e9b07e6504f2ee8d4e7']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(27478,1194) == "811274abb03b6b9dc2595ffe838a2055"
}

