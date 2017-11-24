
rule i445_0b299c8986400922
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i445.0b299c8986400922"
     cluster="i445.0b299c8986400922"
     cluster_size="4"
     filetype = "MS Windows shortcut"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="darkbot dorkbot winlnk"
     md5_hashes="['725a508e423a9d4254a47c0040216bf8','d0148b709aa5ef29a82e7d969182d9da','f86598fa57de2062f6e2c758f4057c40']"

   strings:
      $hex_string = { 0000000000002500530079007300740065006d0052006f006f00740025005c00730079007300740065006d00330032005c0063006d0064002e00650078006500 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
