
rule n26d5_59626926cdbbb912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d5.59626926cdbbb912"
     cluster="n26d5.59626926cdbbb912"
     cluster_size="15"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy kryptik malicious"
     md5_hashes="['7a7eaef5877267068efc41d850cd8e98457de890','b2b7f420ae2b1843ad46e210f7d733552b023d6e','ed841c7e854aaaf9b13f2a9fd2936b2f905c992f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d5.59626926cdbbb912"

   strings:
      $hex_string = { dbc5076fff44d4e3df36d5d790b0e0c28b263c96a269708ed07cb21c497785803977b94ec05ab6f2b77afb6d09355f601af0c70d4dcd6eabf1e9f62304a9e243 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
