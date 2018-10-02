
rule k2319_191a0399c2200912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.191a0399c2200912"
     cluster="k2319.191a0399c2200912"
     cluster_size="11"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script adinject"
     md5_hashes="['270b6a4987ff88432da0c63c135f211b65421afc','bc28f1e6283c2669650f088de35103a9ac365863','fbdc10045482c7b61f4708cadd6b9392609acf3d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.191a0399c2200912"

   strings:
      $hex_string = { 54354c273a225a222c27643370273a2866756e6374696f6e28297b766172204d3d66756e6374696f6e28592c43297b76617220563d43262831312e313645323e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
