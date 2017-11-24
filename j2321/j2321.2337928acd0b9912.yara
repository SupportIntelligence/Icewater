
rule j2321_2337928acd0b9912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2321.2337928acd0b9912"
     cluster="j2321.2337928acd0b9912"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre generickd trojandownloader"
     md5_hashes="['026fb1b8e45b2ca14c7b0fb4c4c74d48','6b6b22fe9e2467268cb29fc2c0ef4e32','c35e44d730ae103ac8ebf56d118d6131']"

   strings:
      $hex_string = { ea506a2e0335afe3b59d866b04928808203231604d0091e1816521441dc76011d1714263e0cf81f8ee4afc1f85ba021f4734017cc63d96066838f0c423b6a712 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
