
rule j26bf_1896ec4ec6230b30
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26bf.1896ec4ec6230b30"
     cluster="j26bf.1896ec4ec6230b30"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dotdo adwarex malicious"
     md5_hashes="['76a5730f6fe023588e6beb10c4f13d3460b16687','bf72cb1dda82a28accacb3c9028f8abb973da691','2eca03b62e6e866170caee8918a6ee1f6e262309']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26bf.1896ec4ec6230b30"

   strings:
      $hex_string = { 7472616c2c205075626c69634b6579546f6b656e3d623737613563353631393334653038392353797374656d2e5265736f75726365732e52756e74696d655265 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
