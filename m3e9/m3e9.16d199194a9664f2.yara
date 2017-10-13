import "hash"

rule m3e9_16d199194a9664f2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.16d199194a9664f2"
     cluster="m3e9.16d199194a9664f2"
     cluster_size="4671 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="shipup razy zbot"
     md5_hashes="['1bd1aa5116653e74e261407097bc0698', '067c4308ad6c98c10caddbe055fa321c', '0d1b63cbbc54cdb42b9acddd2f926745']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(235520,1024) == "e5c64c011f9df09a712f0d7b8c3391f6"
}

