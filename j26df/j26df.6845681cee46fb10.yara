
rule j26df_6845681cee46fb10
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26df.6845681cee46fb10"
     cluster="j26df.6845681cee46fb10"
     cluster_size="343"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="adload nsis cloxer"
     md5_hashes="['bacf3f4df094a12d385ff4c0c8d05aa5f000af92','49d03d11aa9399e24ec6af481acad2d60382c5d5','515edec99448b4c7fefe0c845c4c7ea5dd1ac09f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26df.6845681cee46fb10"

   strings:
      $hex_string = { 2c2669322c266932292069202e7237006b65726e656c33323a3a4765744c6f63616c54696d652869296928723729006b65726e656c33323a3a47657453797374 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
