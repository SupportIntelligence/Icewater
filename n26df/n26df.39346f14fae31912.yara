
rule n26df_39346f14fae31912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26df.39346f14fae31912"
     cluster="n26df.39346f14fae31912"
     cluster_size="173"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="ramnit bmnup nimnul"
     md5_hashes="['0ba1388187c05f64d9cf3fe9e5f3973fb65374dd','3753f41f997a1a422490b14260cd1d60035b224a','07d38ddfc599e1fef1d47e05736153162729086a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26df.39346f14fae31912"

   strings:
      $hex_string = { cb82ed63af07c56611ae83873d06d383a76f857eed4710131eca1655e2a8564dd8c0ff62c9482b9ca1bc038d2668fa5ddf3ee60cdc1beb5b21963bb12dc7fe98 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
