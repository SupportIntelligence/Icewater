
rule k2319_5a12f34bd9eb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.5a12f34bd9eb0b12"
     cluster="k2319.5a12f34bd9eb0b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script browser"
     md5_hashes="['bb371ce248255fa4f340ad09a94906c9a897f1bb','dd9ccb0fffeceaf4115637ad61350624971a4a3b','dab84fc001a2326ae8c31139bcec6ecaa25e2ccc']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.5a12f34bd9eb0b12"

   strings:
      $hex_string = { 627265616b7d3b666f7228766172204a364c20696e20643948364c297b6966284a364c2e6c656e6774683d3d3d282831322e3945322c332e293c30783234423f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
