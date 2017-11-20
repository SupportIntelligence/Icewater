
rule m3e9_3d725b43936bcb12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3d725b43936bcb12"
     cluster="m3e9.3d725b43936bcb12"
     cluster_size="16"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="expiro kakavex blpei"
     md5_hashes="['17232bb24e87b6aed169c0b8a2d42ff9','6c625b3d2bbad152cf8408b7b2762e24','f185db890cea2b7b6a5c773a525d7621']"

   strings:
      $hex_string = { 400096d7d4d5d2d3d0d1dedfdcdddadbd8d9c6c7c4c5c2c3c0c1cecfccf7f4f5f2f3f0f1fefffcfdfafbf8f9e6e7e4e5e2e3e0e1eeefeca6a7a4a5a2a3a0a1ae }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
