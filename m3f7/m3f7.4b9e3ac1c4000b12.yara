
rule m3f7_4b9e3ac1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.4b9e3ac1c4000b12"
     cluster="m3f7.4b9e3ac1c4000b12"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker script"
     md5_hashes="['2233d865af1a37f9af471a5cb6c06dc1','3ac935ecdc2ac2dc9deb2994bf40c564','d0c911694aaa8241093b0acf9aca56af']"

   strings:
      $hex_string = { 55412d34303839313234392d31275d293b0a20205f6761712e70757368285b275f747261636b5061676576696577275d293b0a0a20202866756e6374696f6e28 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
