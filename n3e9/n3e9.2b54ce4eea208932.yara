
rule n3e9_2b54ce4eea208932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.2b54ce4eea208932"
     cluster="n3e9.2b54ce4eea208932"
     cluster_size="42"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply symmi malicious"
     md5_hashes="['0810c3668a008c452e353c29f993326a','100aaa6e12f4d219b5c9ec40f1774d01','9c1d6ec54f34cafab4fd1c753d0823bd']"

   strings:
      $hex_string = { 3a303a343a383a3c3a403a443a483a4c3a503a543a583a5c3a603a643a683a6c3a703a743a783a903a943a983adc3afc3a003b043b083b0c3b483b503b583b60 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
