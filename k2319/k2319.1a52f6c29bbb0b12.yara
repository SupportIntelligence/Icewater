
rule k2319_1a52f6c29bbb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a52f6c29bbb0b12"
     cluster="k2319.1a52f6c29bbb0b12"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script browser"
     md5_hashes="['7ef248246e32572768922c5e8e4bb7637b8f1da9','0a61cf7414d64641d2e58b58cf52b9ade24d6ac8','8e18bf9ba596a7747c2adf39d6a235b661bcdd6b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a52f6c29bbb0b12"

   strings:
      $hex_string = { 4f297b72657475726e20713c4f3b7d2c27543977273a66756e6374696f6e28297b6170705b2822616d222b2835332e3245313e3d28382e33373045322c39293f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
