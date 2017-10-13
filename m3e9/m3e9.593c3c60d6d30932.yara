import "hash"

rule m3e9_593c3c60d6d30932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.593c3c60d6d30932"
     cluster="m3e9.593c3c60d6d30932"
     cluster_size="2463 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="symmi gamarue androm"
     md5_hashes="['0dd210a6869b46377756b1d537c048ac', '1f76afe04b67c3a584f3953adfde6b36', '06db376d9e552c499be1f1c133412295']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(73728,1024) == "80e3e41a26e28d3310ec4358ba4e51aa"
}

