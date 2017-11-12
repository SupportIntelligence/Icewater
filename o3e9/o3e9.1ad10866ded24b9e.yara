
rule o3e9_1ad10866ded24b9e
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.1ad10866ded24b9e"
     cluster="o3e9.1ad10866ded24b9e"
     cluster_size="605"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonster installmonstr malicious"
     md5_hashes="['0009c0d0a49905a03f9d70818abcf089','0019d6fc5cf067e92884eaa7030013e0','05a71f7a160d3d05ccf44b8ff0ac2888']"

   strings:
      $hex_string = { a75b038e1efc9f8e89a801acdabcf5a95501b93e4db25946aefbc5a039747437685a769b698cb3df17f72327c3289681cf1f04fec1f034be19011367ff5909f3 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
