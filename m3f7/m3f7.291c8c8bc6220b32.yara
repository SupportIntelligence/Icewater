
rule m3f7_291c8c8bc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.291c8c8bc6220b32"
     cluster="m3f7.291c8c8bc6220b32"
     cluster_size="7"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker cryxos html"
     md5_hashes="['1724e1def5e54c337dcc9688e042fada','550215e59e3e3298ace8f5a2be638bf3','d919a98359390c1408c1e1b30e62261c']"

   strings:
      $hex_string = { 6261636b67726f756e643a75726c28687474703a2f2f312e62702e626c6f6773706f742e636f6d2f2d425367354e484c4d4f44512f55594d4f505032524f5449 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
