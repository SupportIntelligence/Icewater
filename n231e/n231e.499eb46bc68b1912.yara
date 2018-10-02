
rule n231e_499eb46bc68b1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231e.499eb46bc68b1912"
     cluster="n231e.499eb46bc68b1912"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="andr mobi mobidash"
     md5_hashes="['ea2baa1867711b66f686cf5684d5a07ab8f2e6b4','d5c16c613cefe9eea8720b5de4eafa551c27f469','7e436b16ee6442b55fb67415cec88ea8d405a266']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231e.499eb46bc68b1912"

   strings:
      $hex_string = { 7468726f7700776d656d637079005f5a54564e31305f5f637878616269763131375f5f636c6173735f747970655f696e666f45007365746c6f63616c65007673 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
