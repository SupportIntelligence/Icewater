
rule k3ed_159e3e631cbb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ed.159e3e631cbb0b12"
     cluster="k3ed.159e3e631cbb0b12"
     cluster_size="23"
     filetype = "PE32 executable (DLL) (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul patched"
     md5_hashes="['000f36074906c17633d33fcaf7207f8f','028285435cc19fc48301b493dafb73c8','43489b8063c209e4add3f887374e5fff']"

   strings:
      $hex_string = { 097c0c3c0a7e263c0d74223c20741e57ff151c1187503bf88906730a8a07880347433b3e72f68b0680380075ce80230033c05f5b5ec9c204008b018038277510 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
