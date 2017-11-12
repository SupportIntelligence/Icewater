
rule o3e9_0b916d2f2c744ad3
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.0b916d2f2c744ad3"
     cluster="o3e9.0b916d2f2c744ad3"
     cluster_size="285"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dlboost installmonster malicious"
     md5_hashes="['0075501dcd9ef295d78798967bc7ed50','02428f05f176c2dde978c6f98c3cc2dd','0e64fe257d9100f002aa5c9b73b7826e']"

   strings:
      $hex_string = { 0fcc9eb9564e6b90d1a1547a1688ff2c7bebbfd2f0f8fade847822b4100095c22e74528ec41303e841f4f750fb2abd34f53f6d142db39f0ccbaefea417d804ed }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
