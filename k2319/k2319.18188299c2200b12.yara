
rule k2319_18188299c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.18188299c2200b12"
     cluster="k2319.18188299c2200b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['4dae7599aaebd08b73218b9bc5734ab10601a4a6','ba07eb3271be83713824dfd1f3e61bd45edf9008','19aa66f9d61e34b221afeec04023a1be4d1f789f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.18188299c2200b12"

   strings:
      $hex_string = { 66696e6564297b72657475726e20755b4f5d3b7d76617220473d28307843413c2835322e2c3078323138293f283131372e2c30786363396532643531293a2834 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
