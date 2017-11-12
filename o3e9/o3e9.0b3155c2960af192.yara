
rule o3e9_0b3155c2960af192
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.0b3155c2960af192"
     cluster="o3e9.0b3155c2960af192"
     cluster_size="1049"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonster bundler installmonstr"
     md5_hashes="['0005b49c6f80abf59067adce90de2dcc','00beeaa53f8fb3293016a403af187f5f','039f115c5669d8f07655da14f4521562']"

   strings:
      $hex_string = { 877fc463b3a81d5cf07daffdcbc9eff24801409acccaf9e512283c51c3eaeb8cdb627adaa798614e701c75e618476c4b362c0769e42a8bc1577cf3a50892a3dd }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
