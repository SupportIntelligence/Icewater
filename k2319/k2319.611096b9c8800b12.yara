
rule k2319_611096b9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.611096b9c8800b12"
     cluster="k2319.611096b9c8800b12"
     cluster_size="135"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['71f3c5f89b24487a1571a2aa9e103881ee4cebf0','f050f1b2ece9175c2d0b132b3e02426fbf221d3b','081af6f10bf219a656bfaf238d608d19ba710583']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.611096b9c8800b12"

   strings:
      $hex_string = { 65616b7d3b666f72287661722050375420696e207238733754297b6966285037542e6c656e6774683d3d3d282833302e2c30784235293c28342e343545322c31 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
