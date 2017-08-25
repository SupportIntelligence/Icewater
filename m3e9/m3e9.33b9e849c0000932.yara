import "hash"

rule m3e9_33b9e849c0000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.33b9e849c0000932"
     cluster="m3e9.33b9e849c0000932"
     cluster_size="48 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="swrort elzob zusy"
     md5_hashes="['e68617fb2140d773da9e43faddd95711', 'cd10842fe5121ce19dcfce0bd11a646d', 'cd10842fe5121ce19dcfce0bd11a646d']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(50176,1024) == "ccb05ba3663aace23ac2314559358c25"
}

