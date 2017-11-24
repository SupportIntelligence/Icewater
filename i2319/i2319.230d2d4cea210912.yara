
rule i2319_230d2d4cea210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i2319.230d2d4cea210912"
     cluster="i2319.230d2d4cea210912"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="html phishing script"
     md5_hashes="['4fd3401b6738a08e3fb9ec687bf5358f','61e21615e7174b90464f35106d27d391','f5ef545cc3bb8419bca9ca3fa169ee05']"

   strings:
      $hex_string = { 636861727365743d77696e646f77732d31323532223e0d0a3c7469746c653e457863656c204f6e6c696e65202d2030394b534a444a52343834333938344e4639 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
