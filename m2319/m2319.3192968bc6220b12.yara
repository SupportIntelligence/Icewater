
rule m2319_3192968bc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.3192968bc6220b12"
     cluster="m2319.3192968bc6220b12"
     cluster_size="24"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="hidelink script html"
     md5_hashes="['50c1a5c05d2b41ab3decd46898a4906644e06e3e','593b0ef704a027ba6b6f3ce3d4037594867f5b83','2619531af7242ce888ea602150a50a300ad2a02f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.3192968bc6220b12"

   strings:
      $hex_string = { 305d292c617d2c50534555444f3a66756e6374696f6e2861297b76617220622c633d21615b365d2626615b325d3b72657475726e20572e4348494c442e746573 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
