
rule j2377_0d5642929ee30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2377.0d5642929ee30912"
     cluster="j2377.0d5642929ee30912"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="redirector script redir"
     md5_hashes="['49705895a2409ed827fc7012accc7239','5a57f3bec0a1fd2515215a7988b1cf95','ee4ac2601211179492fdf8868cd30979']"

   strings:
      $hex_string = { 2c2733416d65784b5f67466f704d557a4c6142774352513927293b7661722049783d592827736d636d7236696e70767476272c27416435424d6d47536a767936 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
