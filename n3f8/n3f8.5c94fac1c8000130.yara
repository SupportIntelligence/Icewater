
rule n3f8_5c94fac1c8000130
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.5c94fac1c8000130"
     cluster="n3f8.5c94fac1c8000130"
     cluster_size="145"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="banker androidos asacub"
     md5_hashes="['cd0f5ce5d371cdbfcadaa326aee8d86a045b6016','5e3a07977c09e1d92a92628cb486c5feebb11d75','cf4aac1ff0a3e7fe90d40780f3cf3a8718cf2ed4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.5c94fac1c8000130"

   strings:
      $hex_string = { 50696e673b00344c636f6d2f73717561726575702f6f6b687474702f696e7465726e616c2f6672616d65642f507573684f6273657276657224313b00324c636f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
