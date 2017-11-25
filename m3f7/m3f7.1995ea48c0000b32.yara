
rule m3f7_1995ea48c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.1995ea48c0000b32"
     cluster="m3f7.1995ea48c0000b32"
     cluster_size="45"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['0306fc2c2af74127e9e1a1a9c50c3b93','15dd91d1d5f611fb0eb6b237ab60ddce','6a2c5bb560bd67a500c1974c48ae2ce5']"

   strings:
      $hex_string = { 2c20646f63756d656e742e676574456c656d656e7442794964282748544d4c3127292c207b7d2c2027646973706c61794d6f646546756c6c2729293b0a5f5769 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
