
rule kfc8_51b6229596fb1932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=kfc8.51b6229596fb1932"
     cluster="kfc8.51b6229596fb1932"
     cluster_size="27"
     filetype = "application/zip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="androidos trojansms andr"
     md5_hashes="['05e20b1cdb267a1dbaa70888359b48a1','0cea857cdd09eb8e65414c4dc9e3ed07','9ebf93d44e3a3f040de0e7babf5184a7']"

   strings:
      $hex_string = { 0b70bc3e9c47941eb46f5331ebadc7bf6133e4b8a1ed2664c0dae3738781b1a4dee6300a168f9e6dab3a7f4df70539b9d04a652db1f785ea9af4f3fbd2cae882 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
