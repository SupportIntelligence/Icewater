
rule k2318_274d3399c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.274d3399c2200b32"
     cluster="k2318.274d3399c2200b32"
     cluster_size="71"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redirector"
     md5_hashes="['a2b69c5099aadeea129538476b9abcc9a748d2c7','b9b233697155418dc47456d282df42ec840fee20','8bea880b885ff73c4682710c433ab8f4513d65d0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.274d3399c2200b32"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
