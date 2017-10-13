import "hash"

rule m3e9_33b9e849c0000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.33b9e849c0000932"
     cluster="m3e9.33b9e849c0000932"
     cluster_size="50 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="swrort elzob zusy"
     md5_hashes="['ca50d24f9d990195a3e01c7c39624bde', '3af3e4d4137d75efa2c4c2e34eb48847', 'e1ed4fb09f5b09c1dd5bc235f2ef072d']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(50176,1024) == "ccb05ba3663aace23ac2314559358c25"
}

