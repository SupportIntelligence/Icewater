import "hash"

rule m3ec_299696c9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ec.299696c9cc000b12"
     cluster="m3ec.299696c9cc000b12"
     cluster_size="22 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="malicious betload riskware"
     md5_hashes="['6adc8640ee202a73a0a84ad96c76e260', '5b22ab5d1ac006e9bc7c0a356143005d', '8ccb05fda6273f5ac0f0c05470a9088a']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(6656,256) == "643b14d087d694020dd7e6379bdafaca"
}

