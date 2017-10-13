import "hash"

rule m3e9_65cdf94e324d4bb6
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.65cdf94e324d4bb6"
     cluster="m3e9.65cdf94e324d4bb6"
     cluster_size="345 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['b2d47741ff06551919ea87b2450b34ac', '33b4ac75cfa86f6d7bd0a19fe454020c', 'a63d3ab93239b1bd5e3b1136cb1c3c11']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(78336,1280) == "d3a659f7bca6528afea38f524a5f56aa"
}

