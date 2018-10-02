
rule k26bb_03d39e99c2200932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.03d39e99c2200932"
     cluster="k26bb.03d39e99c2200932"
     cluster_size="39"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="browsefox unwanted yontoo"
     md5_hashes="['0ef40502ca66112b787b2eafc55454735526018b','2c87d73f8850c858e5fe697922534e6a3d0c4aa4','ae730bfbbe2d14e590a2b10ee8ea2e6455ef571e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.03d39e99c2200932"

   strings:
      $hex_string = { 41c5130d3bf3760064f2dfbd9cf1e9237e86991a90ce5bb094b94bc6f4e20334bcd7446ccc52b795ba210c7fde5d27f1fc627082988716463842e151dd737a2d }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
