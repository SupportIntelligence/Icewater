
rule m26bb_781417a9ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.781417a9ca000b12"
     cluster="m26bb.781417a9ca000b12"
     cluster_size="25"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="explorerhijack asponvki malicious"
     md5_hashes="['b9555bff323aa877c412d252bd7a0827a56d305a','efc091d1ab0a3f280832ebb91e1b365a648fbd7e','e7d97ea643baf4c2852ca10c3eb8c8a29d17f847']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.781417a9ca000b12"

   strings:
      $hex_string = { 01c351b8d34d6210f7e1535556578bfac1ef068bc769c0e80300002bc8740383c7018b2dcc50400032db885c241333f68bff807c241300752c3bf77328e830fd }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
