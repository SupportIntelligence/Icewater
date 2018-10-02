
rule k26df_19c33949c0000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26df.19c33949c0000912"
     cluster="k26df.19c33949c0000912"
     cluster_size="451"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="linkury webtoolbar pirax"
     md5_hashes="['0df1a87f303249f6c5d29d015dbff2006bda7b7f','20067d6a42eedbdb6c31c49a08308637a2dd815b','ccf22279874d6dc6820cb034b360db69d34337c3']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26df.19c33949c0000912"

   strings:
      $hex_string = { 77e8f74057656798f75f57e16766e71f57656796e7cf57617745e74e57b577e4675577b5773807db67b5772927dd57e067c5e73b57e277b4e7eb57ea770d178b }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
