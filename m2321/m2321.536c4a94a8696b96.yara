
rule m2321_536c4a94a8696b96
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.536c4a94a8696b96"
     cluster="m2321.536c4a94a8696b96"
     cluster_size="82"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['09494a785809752dc46dd42d63ba325b','12d41557b17ac3200a736e58326cb4af','30580e5288f87b939cac4007c6969e9e']"

   strings:
      $hex_string = { b008481e47a950ab5d4d2cda32bf58fe850c6c9acc43d859fb9b01f64f2b309233ddde9fc06906709c68ce638e0a5bf7c49e9da862df132f003aa17e0222ad7c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
