
rule k3ed_2d1e4b5cda6f4912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ed.2d1e4b5cda6f4912"
     cluster="k3ed.2d1e4b5cda6f4912"
     cluster_size="259"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="browsefox yontoo unwanted"
     md5_hashes="['0025adaaf04515a22714616b25e9fea6','002e36161afb82f3e0f5225e5bb9a978','0f55ca75c07d5c8c6505e7beeb8a8d2c']"

   strings:
      $hex_string = { 428a0284c075f4803a00740749463b4df873db8b451085f6740d562bc65057e8e5f6ffff83c40c5f5e5b8be55dc20c0083ec0c53558b6c24188bd95633f6895c }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
