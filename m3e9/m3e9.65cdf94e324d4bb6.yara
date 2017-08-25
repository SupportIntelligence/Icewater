import "hash"

rule m3e9_65cdf94e324d4bb6
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.65cdf94e324d4bb6"
     cluster="m3e9.65cdf94e324d4bb6"
     cluster_size="311 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['c6ec0b14c9709f2002db0ba31b3915b5', '8f0d81018419b50d9061f762cbc1398d', 'a76e43e7236933029a0beb3584247ba0']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(78336,1280) == "d3a659f7bca6528afea38f524a5f56aa"
}

