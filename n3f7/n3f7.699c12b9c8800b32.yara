
rule n3f7_699c12b9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f7.699c12b9c8800b32"
     cluster="n3f7.699c12b9c8800b32"
     cluster_size="5"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker clicker script"
     md5_hashes="['6d822058599100232c2c2b366901c464','6eccf21282745e1dd7d9b3ecc69663a6','ff12917938291ba07a6b7848aab764a7']"

   strings:
      $hex_string = { 2f3336383935343431352d6c69676874626f785f62756e646c652e637373277d2c2027646973706c61794d6f646546756c6c2729293b0a5f5769646765744d61 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
