import "hash"

rule k3e9_291ff3a9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.291ff3a9c8000b32"
     cluster="k3e9.291ff3a9c8000b32"
     cluster_size="45"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="razy backdoor injector"
     md5_hashes="['0aafe5f743356033d43345223f2b9146','0de65c97813e49058947621ea08d452f','b1525ae6daaba348dc2e4d8cf2b3cb3b']"


   condition:
      
      filesize > 16384 and filesize < 65536
      and hash.md5(22528,1024) == "fbd25a257be15565bffdfafe1358c9fa"
}

