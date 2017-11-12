import "hash"

rule k3e9_1912f3a9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1912f3a9c8000b32"
     cluster="k3e9.1912f3a9c8000b32"
     cluster_size="38"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="razy injector backdoor"
     md5_hashes="['13274fb9e7f3c38d83f11a1df874ba16','1c834c1d2d43d9b2e6693810fef06d05','b4360e0e808c56e0bb9f2fa18d89a119']"


   condition:
      
      filesize > 16384 and filesize < 65536
      and hash.md5(22528,1024) == "fbd25a257be15565bffdfafe1358c9fa"
}

