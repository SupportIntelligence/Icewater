
rule n3ed_0ca3390f1a5b5932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.0ca3390f1a5b5932"
     cluster="n3ed.0ca3390f1a5b5932"
     cluster_size="128"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bpchjo"
     md5_hashes="['02eb2479a4ccc749912ed9b5b606df13','0b898f28f943853d70adc8a2c5a92cf5','97674010998ecf31666492a6db1521ec']"

   strings:
      $hex_string = { 55576a405f4a81e200dce30381c24b594d433bcf8bea7d028bf93bfb761b568d701cff368bc5e891faffff84c059740d4383c6103bdf72ea5e5f5d5bc3686769 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
