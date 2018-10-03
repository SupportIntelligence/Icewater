
rule o26bb_4986b4c59ee30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.4986b4c59ee30932"
     cluster="o26bb.4986b4c59ee30932"
     cluster_size="11"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dealply malicious unwanted"
     md5_hashes="['7d91339ad9b8854b1e87c61b5c9df3fbd9d2f27e','f961c4591e50fa2ff3e4a57fbbe2ff1f9ec2648b','7bfc3feabab9b54ed7d817d692f10204a2199dd8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.4986b4c59ee30932"

   strings:
      $hex_string = { 0bb00bb00bb00be00fd909e0172f042f042f042f042f042f042f042f043100f0175100001810182018300d31000a0230184018501821183100f0175100601870 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
