
rule j26df_2b92938bc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26df.2b92938bc6220b32"
     cluster="j26df.2b92938bc6220b32"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="mplug multiplug script"
     md5_hashes="['9de0140a256d020e05b88ac0280b9e8f7694d46d','3000fdb21090ac708da41f945dd1e78f4c17fe37','59a160eb5d37c225a7614c23d58cf1e3a84d2884']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26df.2b92938bc6220b32"

   strings:
      $hex_string = { 3a22616263647778797a737475767271706f6e6d696a6b6c65666768414243445758595a535455564d4e4f505152494a4b4c4546474839383736353433323130 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
