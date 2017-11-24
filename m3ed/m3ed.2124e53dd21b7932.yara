
rule m3ed_2124e53dd21b7932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.2124e53dd21b7932"
     cluster="m3ed.2124e53dd21b7932"
     cluster_size="71"
     filetype = "PE32 executable (DLL) (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul patched"
     md5_hashes="['01b4cff35186694653c6ad929d81fa63','01f858185944fb81f453c7b4008a7e0e','1310011dd15f0e64633e4741096f73f3']"

   strings:
      $hex_string = { 818b1185d275084083c1043bc772f28b4c24148d4608508913e837f2ffff8b460c8b4c24185f5e89015bc20c0055568bf133ed392e74315333db396e04761e57 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
