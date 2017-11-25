
rule m3f7_41b9200700ab4993
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.41b9200700ab4993"
     cluster="m3f7.41b9200700ab4993"
     cluster_size="8"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['161e5643964150418b55252c77e8c267','1c2125bb5a96d6de4883b35f044be31d','f1c9bc9ba687741d143b486959628a03']"

   strings:
      $hex_string = { 8580373f6d3fde8f4eb79f59c3a47ceb604ddfc9055f6b878d22672c3fe3560e2f16413c5e75f45b3f63b676b56886780399a3088476d6968e92888d0d1e7925 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
