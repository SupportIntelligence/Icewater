
rule m3e9_0916903932316f36
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.0916903932316f36"
     cluster="m3e9.0916903932316f36"
     cluster_size="10"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="scar shyape virtob"
     md5_hashes="['29c26fddde148e72057a89767644a5cf','64e08d45ea4fc503f2d594afe651aad6','e9534e71e5837fa127cf2b24d573010b']"

   strings:
      $hex_string = { 8edb4808384b94491172f687a1050ec858cb2013861b020b0fdfd3be8974abf553a5391e264565756bd1b1ad92951266a6b59ebdd2ebc10d8c3647ec44604c64 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
