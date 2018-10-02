
rule m26bb_2f871ed382988f36
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.2f871ed382988f36"
     cluster="m26bb.2f871ed382988f36"
     cluster_size="187"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="downloadadmin downware riskware"
     md5_hashes="['ee6e6d54bdf9df752aa5860bb54c8c2266777d46','3d00a6b12c484832589900e26f364fd7c073ffcb','bea278420656fbd4ea8b7c4cb7ba9fcdc09a7b23']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.2f871ed382988f36"

   strings:
      $hex_string = { de967f064e0500d0ebaff8f008175525ba35158d6d64ca60793b2646a1d6a9015e57b5ce78aa275cdd54d2734ffebe6cd1e887632bab1b1883c5b843b09b0c47 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
