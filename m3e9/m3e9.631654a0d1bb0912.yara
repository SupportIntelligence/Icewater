
rule m3e9_631654a0d1bb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.631654a0d1bb0912"
     cluster="m3e9.631654a0d1bb0912"
     cluster_size="16"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple rahack malicious"
     md5_hashes="['476c68f3582b2997b7a4a07d6d61874b','59dd0a32d2a52b5926340f8b8727d6ed','f5125954d44ed6df7cf483b4ce11698f']"

   strings:
      $hex_string = { a1559e712baf8157d4f0ce2cd626db46b08e227745e696507e1552b463d947aea569f9f88b73daac1a856628387c7837929958fa6002b1395fa70008408c4ad1 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
