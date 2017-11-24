
rule m2321_299d19e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.299d19e9c8800b12"
     cluster="m2321.299d19e9c8800b12"
     cluster_size="13"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus symmi autorun"
     md5_hashes="['15ad3391ada5d589386a3f69d3ca0f37','1be1de6cb37b5a78677fdf141c3d3757','e2676f373e43c9311ef3ed3c692cfe5c']"

   strings:
      $hex_string = { 38f6a40efd53fe22cdc6e26196829da75cea37bf10ce022cb41ae5490197ed691b4124a0de6a81c07d1248934f43c8eb791dba47f34c1e7f5e8a081c514a0c09 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
