
rule n3e9_13ab56a34a001116
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.13ab56a34a001116"
     cluster="n3e9.13ab56a34a001116"
     cluster_size="112"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="pykspa vilsel malicious"
     md5_hashes="['05c31423b6f4a3254d4f303ec465b274','0f9275ba4ea4d615ad8edc74215eb956','59b11f91167f84d21a7509973a871bde']"

   strings:
      $hex_string = { 78c4d333844f895b18b7ea724bec601f98109cc2c85447c5bce04a67d6d927e8ae39ee6f619e01f7b242946affb96185c999251ef9791187fca5c6685ddd62f0 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
