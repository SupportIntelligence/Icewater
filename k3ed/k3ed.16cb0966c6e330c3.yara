
rule k3ed_16cb0966c6e330c3
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ed.16cb0966c6e330c3"
     cluster="k3ed.16cb0966c6e330c3"
     cluster_size="17"
     filetype = "PE32 executable (DLL) (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul patched"
     md5_hashes="['05fea12d2955f69af02149f323eea31f','0f329161f68d6aa3f58e4fc26bae1c18','c6ff1b620f24640a6238ab44b304aa80']"

   strings:
      $hex_string = { f8730c8bc78a08880b40433b0672f68b0680380075bec6030033c05f5b5ec9c20400b809000280ebf256bef0576f50ff36ff74240cff151c106f5085c0741283 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
