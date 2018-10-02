
rule k2319_1318d4a9c8800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1318d4a9c8800912"
     cluster="k2319.1318d4a9c8800912"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script adinject"
     md5_hashes="['d0ebdc36d8faad9e9227e9d6deaf6ccdd63ec334','5924e6c1230cb97a3c6919468efba4e72370309a','b07c7141294c1eb4b0552dcc652ef04bee442225']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1318d4a9c8800912"

   strings:
      $hex_string = { 6e646f773b666f72287661722079355420696e205330583554297b6966287935542e6c656e6774683d3d3d282832332c3835293e37353f28312e32383945332c }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
