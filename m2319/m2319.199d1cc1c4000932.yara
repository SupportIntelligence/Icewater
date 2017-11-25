
rule m2319_199d1cc1c4000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.199d1cc1c4000932"
     cluster="m2319.199d1cc1c4000932"
     cluster_size="5"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['28a27860799750762fadd867d1602e9b','60395780d01d8c81d9da6bdb498b0e17','bd838a06e9ef538f5900629dfceb1510']"

   strings:
      $hex_string = { 3034374456574c5726616469643d31354244535851424d574a524a5a503239474e3026267265662d72656655524c3d6874747025334125324625324670686f6e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
