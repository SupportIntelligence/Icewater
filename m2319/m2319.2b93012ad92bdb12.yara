
rule m2319_2b93012ad92bdb12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.2b93012ad92bdb12"
     cluster="m2319.2b93012ad92bdb12"
     cluster_size="5"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker clicker script"
     md5_hashes="['0e87027b39e5d54256b988623819637d','292cc3c89af4aa656818a217bd5979c3','995b0da967fc180f274d4999fd414286']"

   strings:
      $hex_string = { 2e636f6d2f7265617272616e67653f626c6f6749443d39373330373934303633343136393138313826776964676574547970653d506f70756c6172506f737473 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
