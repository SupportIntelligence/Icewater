
rule k2319_39156817d9bb0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.39156817d9bb0932"
     cluster="k2319.39156817d9bb0932"
     cluster_size="38"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script flooder loic"
     md5_hashes="['8516225aa229cd9b9096294829a07074e19b183d','eb9a5d5668f6cf98c231f383d5b2687d32189dff','5266d2dfc917aa8dfdb6c1c30808d32d95c243aa']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.39156817d9bb0932"

   strings:
      $hex_string = { 30535531464239734c46774d65436a6a68634f4d414141442b5355524256446a4c745a537654674e424549652f5752526e6d3355385243316e655164736d317a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
