
rule m2319_473168269be30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.473168269be30912"
     cluster="m2319.473168269be30912"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="coinminer coinhive script"
     md5_hashes="['023bd2e95e66dfdfe506b41dfb79f3165418804c','0ade714128c917b9c7fea976bac5e3511f2c7610','b8b55b3b8309dac3ce21dc9d384bc516a4fd6ada']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.473168269be30912"

   strings:
      $hex_string = { 376333613161343862353837615b5f3078646133355b31355d5d293b766172205f30786236396678663d206e657720584d4c487474705265717565737428293b }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
