
rule m3e9_45c29428e156d932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.45c29428e156d932"
     cluster="m3e9.45c29428e156d932"
     cluster_size="7"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="expiro kakavex blpei"
     md5_hashes="['a32d78827a44b2698a56ee108de41fda','b399441da864b5a15181bdf60186825c','d15505a2c74672d1548ebc87fb9d8685']"

   strings:
      $hex_string = { 400096d7d4d5d2d3d0d1dedfdcdddadbd8d9c6c7c4c5c2c3c0c1cecfccf7f4f5f2f3f0f1fefffcfdfafbf8f9e6e7e4e5e2e3e0e1eeefeca6a7a4a5a2a3a0a1ae }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
