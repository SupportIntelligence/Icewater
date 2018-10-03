
rule n26d5_2d9596d992dbb932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d5.2d9596d992dbb932"
     cluster="n26d5.2d9596d992dbb932"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious genx"
     md5_hashes="['9e5a68412eeafdb7d64aaf9173db132dd15060fb','ffd92f537c0b27dee0ba5aa33a0ec1f5c0f6a1ef','a3d7598d67a7af7b13ef06c3034ce34427f4bcab']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d5.2d9596d992dbb932"

   strings:
      $hex_string = { dbc5076fff44d4e3df36d5d790b0e0c28b263c96a269708ed07cb21c497785803977b94ec05ab6f2b77afb6d09355f601af0c70d4dcd6eabf1e9f62304a9e243 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
