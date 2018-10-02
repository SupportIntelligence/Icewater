
rule m3f8_0b4e5ec1c4000914
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f8.0b4e5ec1c4000914"
     cluster="m3f8.0b4e5ec1c4000914"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos jisut lockscreen"
     md5_hashes="['92e398ec039bcee570ff3055e0c75ba9eb3701c5','8948d94507b932219f06bd237439535b182b0837','dddc4aa373fea0664948bda4f384657e2fb70c6e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m3f8.0b4e5ec1c4000914"

   strings:
      $hex_string = { 00050200001a00d700080200001e002500a10200001f003000930200001f000401ad02000020000c008d020000200006009202000020006700ac02000022002c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
