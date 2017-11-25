
rule m3f7_199b9cc9c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.199b9cc9c4000b32"
     cluster="m3f7.199b9cc9c4000b32"
     cluster_size="84"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['02a58dc23046ee78466cbf4561cc74e3','060bf7f61dfe28fd7bb894f9e04c7684','3eeb7cef87d6fe17f21234539802d103']"

   strings:
      $hex_string = { 77205f576964676574496e666f2827426c6f674172636869766531272c2027736964656261722d72696768742d31272c206e756c6c2c20646f63756d656e742e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
