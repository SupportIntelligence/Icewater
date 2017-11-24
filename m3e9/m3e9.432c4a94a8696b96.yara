
rule m3e9_432c4a94a8696b96
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.432c4a94a8696b96"
     cluster="m3e9.432c4a94a8696b96"
     cluster_size="93"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nsis adload clickdownload"
     md5_hashes="['03336db0f8b150b5cbbaf47e139520c5','040e599b7b48fc530ceb78eba35ee6b5','2d0b6d0e118bcb64809ce1d32a0cd901']"

   strings:
      $hex_string = { b008481e47a950ab5d4d2cda32bf58fe850c6c9acc43d859fb9b01f64f2b309233ddde9fc06906709c68ce638e0a5bf7c49e9da862df132f003aa17e0222ad7c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
