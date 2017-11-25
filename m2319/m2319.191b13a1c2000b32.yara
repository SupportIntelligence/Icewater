
rule m2319_191b13a1c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.191b13a1c2000b32"
     cluster="m2319.191b13a1c2000b32"
     cluster_size="8"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker script"
     md5_hashes="['12142cca1461a8c6f32183350d6dbed0','36a9c47df525c105137bce26dc7a0b0b','e7d8262f02b3d25bee210376b982125e']"

   strings:
      $hex_string = { 3a20274c6f6164696e675c78323668656c6c69703b277d2c2027646973706c61794d6f646546756c6c2729293b0a5f5769646765744d616e616765722e5f5265 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
