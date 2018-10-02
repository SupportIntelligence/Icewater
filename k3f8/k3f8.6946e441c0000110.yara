
rule k3f8_6946e441c0000110
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f8.6946e441c0000110"
     cluster="k3f8.6946e441c0000110"
     cluster_size="176"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="congur jisut locker"
     md5_hashes="['d0583fbb2fb2288a7d36ab98d7e254bca7765d75','7a103b1a9aa57e492668f5738a2e0db5dcfef3ca','0f8e3ea65fa69372fcbbc778a705e8c147248bed']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k3f8.6946e441c0000110"

   strings:
      $hex_string = { 2f436f6e6e65637469766974794d616e616765723b00194c616e64726f69642f6e65742f4e6574776f726b496e666f3b00144c616e64726f69642f6f732f4942 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
