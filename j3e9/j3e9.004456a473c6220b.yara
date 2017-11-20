
rule j3e9_004456a473c6220b
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e9.004456a473c6220b"
     cluster="j3e9.004456a473c6220b"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171117"
     license = "RIL-1.0 [Rick's Internet License] "
     family="small madang madangel"
     md5_hashes="['515b571234f987d8230c4521800896d0','a1aff4b78e8d92ce1aa9ec153accd94f','f2aaae13115e63868ae6042a739c7ad4']"

   strings:
      $hex_string = { 66813e4d5a78037901eb75ee0fb77e3c03fe8b6f7803ee8b5d2003de33c08bd683c304408b3b03fae80f00000047657450726f6341646472657373005e33c9b1 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
