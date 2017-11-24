
rule n3e9_4136e448c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4136e448c0000b32"
     cluster="n3e9.4136e448c0000b32"
     cluster_size="22"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus wbna jorik"
     md5_hashes="['052d3ece7a801b9d8e7c3d33acd4f9fa','227de6873cb8d1159388b0ddefe86442','e33c1e9ea2f28f488187c885b796389b']"

   strings:
      $hex_string = { 8b45106a015f57ff75ec8930682c9a400056e83126fdff8bc8e8e627fdff663bc7750fbad48e40008d4de4e86827fdffeb2f7e1b662bc7705c0fbfc050ff75ec }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
