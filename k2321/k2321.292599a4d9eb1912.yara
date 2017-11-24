
rule k2321_292599a4d9eb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.292599a4d9eb1912"
     cluster="k2321.292599a4d9eb1912"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus symmi vbkrypt"
     md5_hashes="['0ede5eca4f427d0dd89fef9fdef408d3','10650ca1640e43f9a82a9a1a5f77d9d1','29e3c31acb9b61d6b48e9615e048f0f4']"

   strings:
      $hex_string = { b10dc613f2a6d484bc293358000b3b38695f9bc4b99d7863572096c549fd9c89cf70b752d36296710c4088d02435b0923d94d8af04c3216ff88e7cf950225415 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
