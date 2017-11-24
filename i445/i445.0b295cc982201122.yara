
rule i445_0b295cc982201122
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i445.0b295cc982201122"
     cluster="i445.0b295cc982201122"
     cluster_size="4"
     filetype = "MS Windows shortcut"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dorkbot darkbot winlnk"
     md5_hashes="['28291aed6bc11eecbb4ea781d0d8465b','318600bb81f65830e45cfd11ece4fdc6','68cd486bf008f713688a8893ed93296f']"

   strings:
      $hex_string = { 000000002500530079007300740065006d0052006f006f00740025005c00730079007300740065006d00330032005c0063006d0064002e006500780065000000 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
