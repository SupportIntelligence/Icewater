import "hash"

rule o3e9_49324292dde98912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.49324292dde98912"
     cluster="o3e9.49324292dde98912"
     cluster_size="4163 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="blackv noobyprotect malicious"
     md5_hashes="['07e2b8f29842adc488db1693a3e2d5b5', '0bd43a0319fe05c70d336eb5ca84baf8', '103899f63a871e421993be474423be7e']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(3093504,1024) == "cf92365a5b8f1a2d111aa0c2629881e7"
}

