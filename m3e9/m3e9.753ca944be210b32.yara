
rule m3e9_753ca944be210b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.753ca944be210b32"
     cluster="m3e9.753ca944be210b32"
     cluster_size="10"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob chirux"
     md5_hashes="['45390c3ad09c3c01c823477e76b5519f','a7beddec448c5a53f831f1ee6c43f3e4','f37361e5582334f3054458a0175e2c4f']"

   strings:
      $hex_string = { b80147657453797374656d496e666f004b45524e454c33322e646c6c0000c8014c6f6164537472696e6741002d00436861725072657641002a00436861724e65 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
