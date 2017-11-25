
rule m3f7_691b9cc9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.691b9cc9c4000b12"
     cluster="m3f7.691b9cc9c4000b12"
     cluster_size="3"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker script"
     md5_hashes="['05c8c9bc34c9fdb8ef7c0138b8a4cea2','5840beeff228437622edf433c65a5d76','80cbbb8121043230445e853274e9efae']"

   strings:
      $hex_string = { 77205f576964676574496e666f2827426c6f674172636869766531272c2027736964656261722d72696768742d31272c206e756c6c2c20646f63756d656e742e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
