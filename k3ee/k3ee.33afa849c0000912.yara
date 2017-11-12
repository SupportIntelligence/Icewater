
rule k3ee_33afa849c0000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ee.33afa849c0000912"
     cluster="k3ee.33afa849c0000912"
     cluster_size="7"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="estiwir advml ageneric"
     md5_hashes="['0104ac00523abc25c401db7658b8e0f7','20f2d13aa32c611ea187fddf718347a7','d5050a484c2f27c7c4359e63621b3e78']"

   strings:
      $hex_string = { ce7833b82f20dab91ac15e53391bd65b9067f525db0402384f6051c4c4c4c42b62eec89e5f7cdac6b03a6450650bbb732a1b7e0e7643289d98dbb1c734bfcbb4 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
