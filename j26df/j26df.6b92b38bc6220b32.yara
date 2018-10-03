
rule j26df_6b92b38bc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26df.6b92b38bc6220b32"
     cluster="j26df.6b92b38bc6220b32"
     cluster_size="21"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="mplug multiplug script"
     md5_hashes="['d58f847b0cc095a75efabd82390b48b850264aa1','aa841f9ac03d954bd3bb7c11a8dfbdf8db93fbae','84efdf4ab2f82248420fa56e46a25f847d8128a4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26df.6b92b38bc6220b32"

   strings:
      $hex_string = { 3a22616263647778797a737475767271706f6e6d696a6b6c65666768414243445758595a535455564d4e4f505152494a4b4c4546474839383736353433323130 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
