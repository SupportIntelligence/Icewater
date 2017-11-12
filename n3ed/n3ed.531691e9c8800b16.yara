
rule n3ed_531691e9c8800b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.531691e9c8800b16"
     cluster="n3ed.531691e9c8800b16"
     cluster_size="40"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bqjjnb"
     md5_hashes="['0354302e441481edf6f3974f5d68e536','0a86d8a08c61c07ae3c045616ba519ea','c1d977d709e71ea7c3c9dc2c23782d28']"

   strings:
      $hex_string = { 53560fb7710633d285f6578d440818761e8b7c24148b480c3bf972098b580803d93bfb720c83c20183c0283bd672e633c05f5e5bc36a0868101c0210e8eafdff }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
