
rule m26bb_692db849c0001932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.692db849c0001932"
     cluster="m26bb.692db849c0001932"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="jaik vobfus aaeh"
     md5_hashes="['be282bd2b651cf3bbae18428e529dc82d813b5c5','8c7b8e1d5a6194f541823450d5deee6dad70aabd','06ab4f6c59702ccd3b8e682183299239df215710']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.692db849c0001932"

   strings:
      $hex_string = { 9815040ce80402006400a81500000600ac0f04349e070a20ffff9e0747022c0c0a200100e509b8039c130b2002009e0d9e130b200200a00da01385200400a20d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
