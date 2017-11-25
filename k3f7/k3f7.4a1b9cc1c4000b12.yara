
rule k3f7_4a1b9cc1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.4a1b9cc1c4000b12"
     cluster="k3f7.4a1b9cc1c4000b12"
     cluster_size="3992"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['000728c271102619fa58be488713424e','000d4c6372f73ce54690667141bdee30','00f5fbf84b6adf499b5a80faa3bd4770']"

   strings:
      $hex_string = { 7970653d27746578742f6a617661736372697074273e0a46422e696e6974287b0a617070496420203a202731353139353638313838333438323034272c0a7374 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
