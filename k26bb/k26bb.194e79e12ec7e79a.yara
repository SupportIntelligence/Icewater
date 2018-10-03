
rule k26bb_194e79e12ec7e79a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.194e79e12ec7e79a"
     cluster="k26bb.194e79e12ec7e79a"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="installcore malicious unwanted"
     md5_hashes="['0cdee7b9bde0a69a283c4cf0dc732e446a449ccd','3d63e1fe4eb912438eaedee43670b2958f69ed02','76770aea5080d87ec19e693a4a4a171eee739553']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.194e79e12ec7e79a"

   strings:
      $hex_string = { b02df7daeb060ae474038ac4aa92508bdc33d2f7350c5d400080c230881343490bc075ed0bc97fe94b8a03aa3bdc75f858c3e81cffffff8b550883fa127205ba }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
