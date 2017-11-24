
rule k3e9_09685923d9eb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.09685923d9eb1912"
     cluster="k3e9.09685923d9eb1912"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus conjar autorun"
     md5_hashes="['099d7391e8c9831a0f13f055cf2c8b7a','15c2bdd346cc4368e3a804a1004373d0','6f942ebb9172ccee1b9395a956b42dfd']"

   strings:
      $hex_string = { d47f296b4bebbfb1095c473546acd6bac70c3d0a39382aaa3cbc14160134929a2fe796ab5443d1ad9cce59f710c269dcc9f6dea693ae66dd1121cff9b3b60699 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
