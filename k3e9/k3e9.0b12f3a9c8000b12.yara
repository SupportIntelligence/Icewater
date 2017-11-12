import "hash"

rule k3e9_0b12f3a9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.0b12f3a9c8000b12"
     cluster="k3e9.0b12f3a9c8000b12"
     cluster_size="56"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor razy injector"
     md5_hashes="['01ef4cf3731ac66e9dabb9fd9fb25e8f','0a8147d05bb25fcc12939a1a05ca0a04','b03e336d49d081c437bc2c2e4a5f16d9']"


   condition:
      
      filesize > 16384 and filesize < 65536
      and hash.md5(22528,1024) == "fbd25a257be15565bffdfafe1358c9fa"
}

