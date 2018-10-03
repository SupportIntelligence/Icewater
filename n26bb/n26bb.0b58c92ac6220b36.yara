
rule n26bb_0b58c92ac6220b36
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.0b58c92ac6220b36"
     cluster="n26bb.0b58c92ac6220b36"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dealply dfqip malicious"
     md5_hashes="['9622e35ee56ba91fead36dfd715305de9eec468d','5ae7bf577b996a78b9a662d012c1baaa7ec18945','998db23165ea7373de527752dd472e039a7aa7ca']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.0b58c92ac6220b36"

   strings:
      $hex_string = { 5f5e5bc3905e5bf6c1030f8425f6ffff31c0c38bc0538d58ff83e3fce860f7ffff83f80119c98d140309cb81fb2c0a04007310f7dbd9eedd141383c30878f889 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
