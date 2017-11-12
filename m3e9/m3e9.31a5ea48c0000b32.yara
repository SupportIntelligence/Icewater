
rule m3e9_31a5ea48c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.31a5ea48c0000b32"
     cluster="m3e9.31a5ea48c0000b32"
     cluster_size="76"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob malicious"
     md5_hashes="['082c860c50388a6e673cae0a31cbabe3','08ae8a79075576f8c59af09ecb8bd16b','50efe8c6a8a9770389b35ab72825eaab']"

   strings:
      $hex_string = { 3b5232095751300a6b4a2c096f763b0792773d0695773e069d6a3909a144270f9e3a210fab472614be733d24e5934d30fdae5c34ffb2653fffb66d49ffb7704c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
