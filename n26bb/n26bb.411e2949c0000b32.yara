
rule n26bb_411e2949c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.411e2949c0000b32"
     cluster="n26bb.411e2949c0000b32"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="explorerhijack amgmmqii patched"
     md5_hashes="['9ffad6b0089014f22925bc4f4b60c75d6f116535','51dca735fed9ad56d3866c77a4ccba505d7f1282','655c9c76181f421a48ebe37732817e44879d1815']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.411e2949c0000b32"

   strings:
      $hex_string = { 01c351b8d34d6210f7e1535556578bfac1ef068bc769c0e80300002bc8740383c7018b2dcc50400032db885c241333f68bff807c241300752c3bf77328e830fd }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
