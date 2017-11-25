
rule m3e9_13e7ea89c0000916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.13e7ea89c0000916"
     cluster="m3e9.13e7ea89c0000916"
     cluster_size="45"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installcore malicious classic"
     md5_hashes="['02192b1654f5c7939fe1160b13a2ee82','02ba7756c6a095da7a0acfb6ed05123c','626a04abd17e96dadc0d5e18f33fe7ca']"

   strings:
      $hex_string = { 7db4c18511a648f025a996078b0ed0aefebf5ce050d898f3e52cdb3f5e335db592ce2e5b678329af3e4e3410451308bdf19e7eadb3a4ecaa361f144dc26f31b8 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
