
rule p26ef_55999cc1cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=p26ef.55999cc1cc000b12"
     cluster="p26ef.55999cc1cc000b12"
     cluster_size="67"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="expiro malicious susp"
     md5_hashes="['9458f682a39f78df0011b1d944a0d38744d71b51','54e7eeb69f74ba39223f136d20694da691a6da78','276cc6bc4eb0ad40b55858b8d2fd99f1f7ee964b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=p26ef.55999cc1cc000b12"

   strings:
      $hex_string = { 09115b3cf992b25df67d1cbf298d7b98d878b3d90cf543e0ffcc4c529da919cfef7932546dd4477458f8653eed16274e8501106f2b80a66b82d6963a5949d261 }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
