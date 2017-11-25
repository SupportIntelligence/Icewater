
rule m2377_5b1a92c9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.5b1a92c9c8000b12"
     cluster="m2377.5b1a92c9c8000b12"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker script html"
     md5_hashes="['5b924ed9a19402c2b9d9a8b400af8698','64bbb88ead81c559d1ae5ada97f1d595','bc1291751a31c8becc243cc100598590']"

   strings:
      $hex_string = { 2e636f6d2f7265617272616e67653f626c6f6749443d36373539373836373937393032323139333126776964676574547970653d48544d4c2677696467657449 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
