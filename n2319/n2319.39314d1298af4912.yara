
rule n2319_39314d1298af4912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.39314d1298af4912"
     cluster="n2319.39314d1298af4912"
     cluster_size="27"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script miner coinminer"
     md5_hashes="['dea21e97c2895df2bdaf88511b8728b3584b9c1a','902df1263e9e5d21a4fb6b1f0c2e11de672aa3d2','fe26d59d441018534b5ee5fe7084204e7176f50f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.39314d1298af4912"

   strings:
      $hex_string = { 732a5c5d2f672c223d272431275d22293b696628216b2e6973584d4c287029297472797b6966286e7c7c216f2e6d617463682e50534555444f2e746573742871 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
