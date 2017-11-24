
rule m2321_139d6a48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.139d6a48c0000b12"
     cluster="m2321.139d6a48c0000b12"
     cluster_size="27"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="murofet swisyn zbot"
     md5_hashes="['05ed2fdfa528a40fcfcead9a202c7889','09bb214c99d0de0d614b1de56be4804e','95d7586db255ecfc8db5e80eb9467d5f']"

   strings:
      $hex_string = { 24dc39eda86be05e4f0c4c23655d801ac941f6a3d261b64d7cc06490a6ab20b5774485d46e60bd8815f47cd58c435156032ada3540beae3ed37a1c8af994c429 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
