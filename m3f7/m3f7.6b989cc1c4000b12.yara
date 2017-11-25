
rule m3f7_6b989cc1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.6b989cc1c4000b12"
     cluster="m3f7.6b989cc1c4000b12"
     cluster_size="20"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['01b1385264c4dfc1f772baf28c188d73','1c0ba8552b1cf744f2dd362bc0bec8d4','e6e3ce7e6bc5210e7b9ea82e8b0369a7']"

   strings:
      $hex_string = { 722e636f6d2f7265617272616e67653f626c6f6749443d3638373231373038313637313339353634393826776964676574547970653d426c6f67417263686976 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
