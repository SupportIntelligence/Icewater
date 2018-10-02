
rule n2319_13db03a9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.13db03a9c8000b12"
     cluster="n2319.13db03a9c8000b12"
     cluster_size="58"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script miner coinminer"
     md5_hashes="['69b2f7ac0b3a6e7b0754095e5abd99e0a4417529','a450e57f68eb477168cd1c7a3116f8246bcf2ed2','9803f8487443b64ef51c74355632db830e17f450']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.13db03a9c8000b12"

   strings:
      $hex_string = { 2131292e6c656e6774687d7d293b76617220712c4c3d2f5e283f3a5c732a283c5b5c775c575d2b3e295b5e3e5d2a7c23285b5c772d5d2b2929242f3b28772e66 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
