
rule k3e9_291cad6d9c9b0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.291cad6d9c9b0b12"
     cluster="k3e9.291cad6d9c9b0b12"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy emotet"
     md5_hashes="['26a7769f905840718aec2766d98daa96','63486d57e564b5e39e4734e888ff97a4','ce7d386b58fce3bb567b2c6d76ccbf30']"

   strings:
      $hex_string = { 496b664aaa67882b734595d3847533f8f5b9dcb353d85f0ff7ddd687312d560cd3b4fe3aa9540263f9dc76f0107059423e572a93eafcfd7b8606cc4890bed49f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
