import "hash"

rule k3e9_2289c62d44534aba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2289c62d44534aba"
     cluster="k3e9.2289c62d44534aba"
     cluster_size="6994"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="picsys hidp prng"
     md5_hashes="['001a6c27c5afb39f607f29c53d52e5f5','001c62f01240ec5026e6bedf390169e7','00f0cf6432627736a91b23190baf2789']"


   condition:
      
      filesize > 65536 and filesize < 262144
      and hash.md5(32768,16384) == "e000e063c859e5f7d05a0d81d53ea5de"
}

