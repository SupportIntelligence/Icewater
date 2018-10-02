
rule m26bb_13636ed144000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.13636ed144000932"
     cluster="m26bb.13636ed144000932"
     cluster_size="25"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="installcore dealply malicious"
     md5_hashes="['7b087d8967c3089e7074fe1ef890a376edf56425','4360958fd80b2b6b2241c65c5dc4c98529699110','5a96012571a3cb856b7df6fc80f6476fbb80c2de']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.13636ed144000932"

   strings:
      $hex_string = { d0c516e093ad4f430044b48f9234fa568a9cd903b1056042d5f7b72164145331fc9f49488d6ba1cae18139ce5f332cf65861d3db98173d6c7f09dee60b3bf8fe }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
