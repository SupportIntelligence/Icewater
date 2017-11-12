import "hash"

rule k3e9_609054e96e210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.609054e96e210b12"
     cluster="k3e9.609054e96e210b12"
     cluster_size="1152"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="heuristic cerber engine"
     md5_hashes="['001260070c496427eb5fb52bfbfb73af','004dbb9e9f3153c338ff8394271a0ed0','036266421672db4e4684566eb926fe7e']"


   condition:
      
      filesize > 16384 and filesize < 65536
      and hash.md5(20480,4096) == "339ddab8ef83a7e27260fd9a395f05e5"
}

