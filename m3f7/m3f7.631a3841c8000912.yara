
rule m3f7_631a3841c8000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.631a3841c8000912"
     cluster="m3f7.631a3841c8000912"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['2ebf7597d5e8d0ea0cb445cbcdb1f9ca','4860afa3ddec1c97c1f270b4ebadae42','c09f36bc6d428887c980ecd597371c1c']"

   strings:
      $hex_string = { 77205f576964676574496e666f2827426c6f674172636869766531272c2027736964656261722d72696768742d31272c206e756c6c2c20646f63756d656e742e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
