
rule n3e9_419aa56bc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.419aa56bc6220b12"
     cluster="n3e9.419aa56bc6220b12"
     cluster_size="37"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="kazy loadmoney cobra"
     md5_hashes="['07fa3fff43f3238e0fb53115fb941c7c','0a262b17287d629165128e4ff3b84607','71bb1d7852a03d4e0c9af3e5f9e54e64']"

   strings:
      $hex_string = { 41646d696e6973747261746f72222075694163636573733d2266616c7365223e3c2f726571756573746564457865637574696f6e4c6576656c3e0a3c2f726571 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
