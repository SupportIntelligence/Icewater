
rule m2321_41122966dabb0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.41122966dabb0932"
     cluster="m2321.41122966dabb0932"
     cluster_size="49"
     filetype = "PE32+ executable (GUI) x86-64"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="runbooster classic euhdtt"
     md5_hashes="['02aa64086119fe067218d9e913517f5d','19e39f92911497f43c8dd3e65dbe30a5','663d39e96d943d913a46e25f6eef53cc']"

   strings:
      $hex_string = { 5d6973e937baf6af8634a2b7f2eb61e5e678ce68c554cf199d982cff654d8462f77f9b600e0d03d6fe5cc8c07b1a74362f55118af524bdb01d28b68fd775f371 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
