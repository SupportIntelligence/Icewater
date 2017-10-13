import "hash"

rule m3e9_611c9cc9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.611c9cc9cc000b12"
     cluster="m3e9.611c9cc9cc000b12"
     cluster_size="4337 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="sality bakc beygb"
     md5_hashes="['1402df411c2d4cf32b789d59228ba38d', '0510ad1154012c70ceae5e1a3d9753a7', '09e4cb9a95535338919b6c609b31293f']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(67072,1024) == "c065e5bedd7c5e7fd1fadb279e0ea335"
}

