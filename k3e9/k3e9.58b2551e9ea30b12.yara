import "hash"

rule k3e9_58b2551e9ea30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.58b2551e9ea30b12"
     cluster="k3e9.58b2551e9ea30b12"
     cluster_size="2825"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre kryptik trojandownloader"
     md5_hashes="['00023ca5e200aa0c9ad0b9518889e457','001bd6cf5020835682d44158e8a605b4','027a1064ecba73c42d9d7b39d9bc1c45']"


   condition:
      
      filesize > 16384 and filesize < 65536
      and hash.md5(16384,4096) == "d9aececb25d514c47bbcbd0f80f02168"
}

