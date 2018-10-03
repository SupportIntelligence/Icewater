
rule m2319_439b94a9c8800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.439b94a9c8800912"
     cluster="m2319.439b94a9c8800912"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="faceliker clicker html"
     md5_hashes="['852e490d3b47a1bca68abc483d4eedafed65bb36','a26a310b558cb4f780b21f819d8df0fc2cf9294f','8146589343db950139e856c3471fec9ef13c5203']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.439b94a9c8800912"

   strings:
      $hex_string = { 30535531464239734c46774d65436a6a68634f4d414141442b5355524256446a4c745a537654674e424549652f5752526e6d3355385243316e655164736d317a }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
