
rule k2319_610fb849c8000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.610fb849c8000912"
     cluster="k2319.610fb849c8000912"
     cluster_size="14"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="multiplug script browext"
     md5_hashes="['59f03f5d31512dcd904cb488491768ec250e441e','512839321d03c8c1ec2efce14ff10a9973fa8584','376ac9fe68a58d3080abd0e32519dc9226bbab00']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.610fb849c8000912"

   strings:
      $hex_string = { 297b72657475726e2059213d523b7d7d3b2866756e6374696f6e28297b7661722059303d226f77222c6f353d22656e65222c54303d224c69222c7a303d226445 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
