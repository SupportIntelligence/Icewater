
rule m2377_1a991cc1c4000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.1a991cc1c4000912"
     cluster="m2377.1a991cc1c4000912"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fakejquery script trojandownloader"
     md5_hashes="['6f27b7a67ba1463e672605b537142c24','8c7f5656e03c432b8420335037060274','8f168c50f17bc32811ba0c530bf3d148']"

   strings:
      $hex_string = { 6c6f667468756d62732f3132307836302f696d616765732f73746f726965732f4752414e2d4d415155494e415249412d324d494c31322d342d312e6a70672220 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
