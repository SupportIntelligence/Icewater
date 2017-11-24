
rule m2319_19989cc1c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.19989cc1c8000b32"
     cluster="m2319.19989cc1c8000b32"
     cluster_size="7"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker likejack clicker"
     md5_hashes="['6247a7e70477f2881a5eb600d254935f','7c3138a3d2de211ff163356ca3004bc6','efaafc44d601df5940d4221db34ea949']"

   strings:
      $hex_string = { 273a20274c6f6164696e675c78323668656c6c69703b277d2c2027646973706c61794d6f646546756c6c2729293b0a5f5769646765744d616e616765722e5f52 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
