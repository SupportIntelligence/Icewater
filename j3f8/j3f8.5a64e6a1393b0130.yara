
rule j3f8_5a64e6a1393b0130
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f8.5a64e6a1393b0130"
     cluster="j3f8.5a64e6a1393b0130"
     cluster_size="192"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="shedun androidos origin"
     md5_hashes="['5722c8087a3289631b34fed1f3928266acdfe412','facecc2606b9f227053c54af15d50bcf6528fc97','07dcfb92c7aaae4973dd1feb2f456f01a927e5d5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j3f8.5a64e6a1393b0130"

   strings:
      $hex_string = { 696f2f496e70757453747265616d3b00164c6a6176612f696f2f4f757470757453747265616d3b00134c6a6176612f6c616e672f426f6f6c65616e3b00104c6a }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
