
rule m3e9_7a48d59b8a37cd91
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.7a48d59b8a37cd91"
     cluster="m3e9.7a48d59b8a37cd91"
     cluster_size="8"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus barys malicious"
     md5_hashes="['67c1e0c8315d81be2c0924d71fa3bee8','a5cc7455c5ea1d1395f53d22b0ebb941','dc83c511ab0e0b5f03246c30c3edea6e']"

   strings:
      $hex_string = { c8813e3c344300895db8895da8895da4895da07405e815b2fdff83c644391e750b5668e48e4000e8bdaffdff8b3e8d4da451578b07ff50243bc3dbe27d11bbd4 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
