
rule m231b_4bd36949c0000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m231b.4bd36949c0000912"
     cluster="m231b.4bd36949c0000912"
     cluster_size="11"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script clicker faceliker"
     md5_hashes="['21c9f0edf2e095ef2968024329d89e04cb75a3d8','631fa18618871c7f5a933ac7ee7dab50d9a3aeea','9263a9f5b15706637ef40986ce6ddd801e47e912']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m231b.4bd36949c0000912"

   strings:
      $hex_string = { 2d74573069427a4e6345716f2f554c6a544c594d595458492f41414141414141414731672f66436575396c336c696a302f733639382f626f6479777261705f62 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
