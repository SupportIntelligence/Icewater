
rule m3e9_3d72c5ba096bcb12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3d72c5ba096bcb12"
     cluster="m3e9.3d72c5ba096bcb12"
     cluster_size="10"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="expiro kakavex malicious"
     md5_hashes="['7f8ae346ff1319b881965bf51a1d6ee7','a0447c37fa569e0a24431c993d17748a','dbcbff9ac2f164036a0509fe690398ab']"

   strings:
      $hex_string = { 400096d7d4d5d2d3d0d1dedfdcdddadbd8d9c6c7c4c5c2c3c0c1cecfccf7f4f5f2f3f0f1fefffcfdfafbf8f9e6e7e4e5e2e3e0e1eeefeca6a7a4a5a2a3a0a1ae }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
