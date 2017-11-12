import "hash"

rule k3e9_58b2551e9ea31b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.58b2551e9ea31b12"
     cluster="k3e9.58b2551e9ea31b12"
     cluster_size="1682"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre trojandownloader kryptik"
     md5_hashes="['00860f250b0587f306dfd1a8695c99e9','01104941023bdf4ffac00e9fd0dc7d65','0513eb648a2c9988fe91c846a6900a7b']"


   condition:
      
      filesize > 16384 and filesize < 65536
      and hash.md5(16384,4096) == "d9aececb25d514c47bbcbd0f80f02168"
}

