
rule j2319_611a92b9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2319.611a92b9c8800b12"
     cluster="j2319.611a92b9c8800b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="multiplug megasearch browsermodifier"
     md5_hashes="['02697d58b8db9c1d2e82c95c1da696dec4d40166','f28ab178012ef037d968e10575312de2c87e7d53','64b0b82f21bb02ee85ebf8bd75da59ccd391fa61']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j2319.611a92b9c8800b12"

   strings:
      $hex_string = { 3a22616263647778797a737475767271706f6e6d696a6b6c65666768414243445758595a535455564d4e4f505152494a4b4c4546474839383736353433323130 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
