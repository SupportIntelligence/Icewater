
rule n26d5_2d9194d992dbbb32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d5.2d9194d992dbbb32"
     cluster="n26d5.2d9194d992dbbb32"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious gifq"
     md5_hashes="['f473f16926ffcbff5f84b380afe1b704a67ba280','0022386809366303653d78495c44ec7a9bcf0860','145fb869c4e8e802bdad728bb35ee1ba1a68a9a4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d5.2d9194d992dbbb32"

   strings:
      $hex_string = { dbc5076fff44d4e3df36d5d790b0e0c28b263c96a269708ed07cb21c497785803977b94ec05ab6f2b77afb6d09355f601af0c70d4dcd6eabf1e9f62304a9e243 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
