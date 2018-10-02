
rule o26c0_59eb2802d0000132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26c0.59eb2802d0000132"
     cluster="o26c0.59eb2802d0000132"
     cluster_size="182"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="deay malicious kryptik"
     md5_hashes="['76c3c0319e1e334318160267701e57827a440859','2d799e656982aed4c80d45506b8999777887cf21','672aa689c438533e35d1b428fc478ad43b633aa9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26c0.59eb2802d0000132"

   strings:
      $hex_string = { 000000000000f03fcf956b86a17cb3bf63a9aea6e27dd83f000000e0ed2c67bc000000000000f03f7912fa73683abebf3bf606385d2bde3f00000020890d5e3c }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
