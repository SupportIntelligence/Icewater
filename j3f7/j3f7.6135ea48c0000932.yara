
rule j3f7_6135ea48c0000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f7.6135ea48c0000932"
     cluster="j3f7.6135ea48c0000932"
     cluster_size="17"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="iframe html iframeref"
     md5_hashes="['29b9d9094abb51adf9667a7a057bc49f','354bb686252d2d0b2f3baac0c1ba64b2','e3e4038cc4ce5d66d72fecfccaf9362d']"

   strings:
      $hex_string = { 65743e3c2f666f6e743e3c736372697074206c616e67756167653d226a61766173637269707422207372633d22687474703a2f2f666174616c2e72752f616466 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
