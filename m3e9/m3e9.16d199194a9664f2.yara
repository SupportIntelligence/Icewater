import "hash"

rule m3e9_16d199194a9664f2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.16d199194a9664f2"
     cluster="m3e9.16d199194a9664f2"
     cluster_size="4574 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="shipup razy zbot"
     md5_hashes="['0e5e2d68785c5542203348b5974d0ed0', '0db915402b497671ce7126178319bb4c', '0ce9352a430acd4e9ae8e5ce53f85390']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(235520,1024) == "e5c64c011f9df09a712f0d7b8c3391f6"
}

