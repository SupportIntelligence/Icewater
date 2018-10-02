
rule n2726_7151e448c0000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2726.7151e448c0000912"
     cluster="n2726.7151e448c0000912"
     cluster_size="20"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="symmi malicious stantinko"
     md5_hashes="['db7ac91c38fb15ccb70cf4f0a17eb83380f2ccbe','66fb0aefda3731a6b67e662a25962a31f11e1dfe','51a256e9f7395912e9d83baaf6f901846dea3098']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2726.7151e448c0000912"

   strings:
      $hex_string = { 38333634372c2026756c537472696e674c656e2900688c9c1a1068b49c1a1053e834ece5ff8b45f083c40cc645fc0085c074068b0850ff5108bb57000780e9e4 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
