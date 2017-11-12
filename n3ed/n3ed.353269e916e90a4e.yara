
rule n3ed_353269e916e90a4e
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.353269e916e90a4e"
     cluster="n3ed.353269e916e90a4e"
     cluster_size="13"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul malicious"
     md5_hashes="['1a8b03369a55426d643622aa5aec6931','1d9738dec2c3bf49a5cd7b370b7bb73a','fb329ca59b4e20012740c9eec27e1c0e']"

   strings:
      $hex_string = { 004142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a303132333435363738392b }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
