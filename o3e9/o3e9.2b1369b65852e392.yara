
rule o3e9_2b1369b65852e392
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.2b1369b65852e392"
     cluster="o3e9.2b1369b65852e392"
     cluster_size="337"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dlboost bundler installmonstr"
     md5_hashes="['01ab1ef2e82e27729088b351c8927aea','01e9173b08c5c52cf11180eaa938f303','0faf580de16df9b20d7d14d576480a81']"

   strings:
      $hex_string = { edb9a07d6a1cf5f972830a3188efffe7291a3edf8d387a3c691da3e236d164549e06d98ec3e4daa4f69577bfe8c8b1d20813527f302f474f39491e65111921a6 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
