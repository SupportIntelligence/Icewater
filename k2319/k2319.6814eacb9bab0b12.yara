
rule k2319_6814eacb9bab0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.6814eacb9bab0b12"
     cluster="k2319.6814eacb9bab0b12"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script asmalwsc"
     md5_hashes="['8957c27111c71c71a5d312ba6583939cda996e3c','863c30741dd69d395af849bd1910e553ae9c6efc','3f7234f94c1fec7da276124c0ca4e8ffaf48c8bc']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.6814eacb9bab0b12"

   strings:
      $hex_string = { 38293f28307837382c313130293a2835332c3078314538292929627265616b7d3b76617220443059373d7b27443239273a22616368222c27673343273a227469 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
