
rule n2326_33b19699dee30916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2326.33b19699dee30916"
     cluster="n2326.33b19699dee30916"
     cluster_size="53"
     filetype = "application/zlib"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="bundlore bnodlero bundloreca"
     md5_hashes="['0776c75ab1ab1102a7027e6d15086a11','0816cf345fbecad1bd653f5cf3c186df','3604c1c3acce0e0fc5f0f89ad6a163ae']"

   strings:
      $hex_string = { 99c39197419b0ce23e3d289d575eadd1966cccce8505b7a6c00f89278ba18aac0902163fd04b285806b9491e7390238810820de69e22e44d33bcde15261b54cd }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
