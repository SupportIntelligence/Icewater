
rule kfc8_51b6aa9d96fb1932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=kfc8.51b6aa9d96fb1932"
     cluster="kfc8.51b6aa9d96fb1932"
     cluster_size="24"
     filetype = "application/zip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="androidos trojansms andr"
     md5_hashes="['0d370e3d6f5635eaf1fd75b2dd36d264','11e53b2b39b677877796022f22d8d7a8','ac7c99adaa0fa16eadf281f85609cdc8']"

   strings:
      $hex_string = { 0b70bc3e9c47941eb46f5331ebadc7bf6133e4b8a1ed2664c0dae3738781b1a4dee6300a168f9e6dab3a7f4df70539b9d04a652db1f785ea9af4f3fbd2cae882 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
