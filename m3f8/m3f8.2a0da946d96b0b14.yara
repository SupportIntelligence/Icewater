
rule m3f8_2a0da946d96b0b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f8.2a0da946d96b0b14"
     cluster="m3f8.2a0da946d96b0b14"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="droidkungfu androidos kungfu"
     md5_hashes="['baf1eb6dc26ec2d559eafcd2e030a2e024f61fd0','5932f42891a18226c5f5c423d99a5e5f57829f79','c02d21ad0d05b76302825ea404fd4acd57b43970']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m3f8.2a0da946d96b0b14"

   strings:
      $hex_string = { bdefbc8ce8afb7e59ca8e9809ae79fa5e4b8ade98089e68ba922e585b3e997ad55534220e5ad98e582a822000353444b00045350414e00065354524f4b450009 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
