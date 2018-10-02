
rule n26bb_29a57cc1c8001116
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.29a57cc1c8001116"
     cluster="n26bb.29a57cc1c8001116"
     cluster_size="366"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious attribute bxpp"
     md5_hashes="['19a13efa389c2d77c13283fc52ddba7828d44d46','2aa3783681e367169f7e891d4587f6be51dc904e','7844924da7335dff9f4c24dd6f90947595a774e2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.29a57cc1c8001116"

   strings:
      $hex_string = { 68844642005056e84df2ffff83c40c85c075768d4e02397d147403c606458b55188b420c803830742d8b52044a7906f7dac646012d6a645b3bd37c088bc299f7 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
