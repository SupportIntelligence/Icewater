
rule m3ed_5326694140000132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.5326694140000132"
     cluster="m3ed.5326694140000132"
     cluster_size="122"
     filetype = "PE32 executable (DLL) (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit malicious nimnul"
     md5_hashes="['0133d4a53ca149c102eebc2728a500ba','01e342c38ee372a3ab622e6c5ca6a2b7','0b0d55b56afb99f9326d812030bd9f6a']"

   strings:
      $hex_string = { 33db833d80ba222e017e0c6a0456e87b0d00005959eb0ba1b0b7222e8a047083e00485c0740d8d049b8d5c46d00fb63747ebcf83fd2d8bc37502f7d85f5e5d5b }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
