
rule o26bb_1382b339c9800932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.1382b339c9800932"
     cluster="o26bb.1382b339c9800932"
     cluster_size="34"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="graftor dangerousobject fraudload"
     md5_hashes="['748ed850fe30e31459ce0c4e371d0f9beef88909','aeb27828671e087bd19061e45a859ef0254a8921','767eeae5e18a65f68f360b4cc10d3a433ad62dab']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.1382b339c9800932"

   strings:
      $hex_string = { cde0e6ece8f2e520f7f2eee1fb20f3e2e8e4e5f2fc20eef0e8e3e8ede0eb220100010a4964656e74696669657206216d5f7042746e56696577536f757263652e }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
