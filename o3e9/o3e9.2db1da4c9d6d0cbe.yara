
rule o3e9_2db1da4c9d6d0cbe
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.2db1da4c9d6d0cbe"
     cluster="o3e9.2db1da4c9d6d0cbe"
     cluster_size="195"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonster installmonstr malicious"
     md5_hashes="['0082a56be0ff140beb9e157c4c2ab288','0146d472f1cda5f34d8ad120c0efff0b','0d5ff143a5936422707675509659f939']"

   strings:
      $hex_string = { b70f84677749686b1dfb069ecf47de3349c01cf7992399b981de9734f9df0e6618ca1115bb3f50216227025f4292e5810523644ad2f1482943600fc3be730031 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
