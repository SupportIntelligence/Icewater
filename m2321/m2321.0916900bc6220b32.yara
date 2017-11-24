
rule m2321_0916900bc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0916900bc6220b32"
     cluster="m2321.0916900bc6220b32"
     cluster_size="14"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="scar shyape virtob"
     md5_hashes="['077e09d80453d44c0c116b42ef5c79b0','0fa25216397f744211edd62dd34e7092','c44d3a64beb14a39519adae10aa5fc88']"

   strings:
      $hex_string = { 8edb4808384b94491172f687a1050ec858cb2013861b020b0fdfd3be8974abf553a5391e264565756bd1b1ad92951266a6b59ebdd2ebc10d8c3647ec44604c64 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
