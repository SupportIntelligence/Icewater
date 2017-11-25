
rule i3e9_050b2a94c616e115
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3e9.050b2a94c616e115"
     cluster="i3e9.050b2a94c616e115"
     cluster_size="107813"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre razy waski"
     md5_hashes="['00009fa86f08ffb0e9ae9b0f62d53d27','0002648e512a1c99d7010480ea51cc17','00182fcfdfd2c865b152a686b4ad6224']"

   strings:
      $hex_string = { b2464cc550d044c4f1f00b43e03be764052a14cb1918857a38b10d510269d8ddc1574f5bb474b05e2880795acde594b99a9d8f3d363e87daff5ff5c88cbeee32 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
