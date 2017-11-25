
rule k3e9_193e79e3dec34916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.193e79e3dec34916"
     cluster="k3e9.193e79e3dec34916"
     cluster_size="10199"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installcore unwanted advml"
     md5_hashes="['000f6fc8b13d610d8c5478731bc51df4','001fc91d5d51db121782bd479cde07f4','00805f9e997fa4f67bbbe3ce028f5f23']"

   strings:
      $hex_string = { 111100161616001c1c1c002222220029292900555555004d4d4d004242420039393900ff7c8000ff505000d6009300ccecff00efd6c600e7e7d600ada9900033 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
