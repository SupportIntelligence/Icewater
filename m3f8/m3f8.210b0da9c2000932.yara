
rule m3f8_210b0da9c2000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f8.210b0da9c2000932"
     cluster="m3f8.210b0da9c2000932"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="banker androidos andr"
     md5_hashes="['6dde9fdbf9d8ab9c84c9f3863063aba2468a058f','205db1bb194a0d7113bfda9bcee67cea959f04a2','6cff5cdcdf768ba227d6852f9d37fd3754820071']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m3f8.210b0da9c2000932"

   strings:
      $hex_string = { 154c6f72672f6a736f6e2f4a534f4e4f626a6563743b000c4d414e554641435455524552000e4d41585f4241434b4f46465f4d53000b4d43727970742e6a6176 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
