
rule o3fd_6332d6cbcc000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3fd.6332d6cbcc000932"
     cluster="o3fd.6332d6cbcc000932"
     cluster_size="197"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="expiro allinone ccchoh"
     md5_hashes="['00647039a6cb0fbd55732b7e10b15cc4','01727b9545b94a9f51d1087cf26f4def','429f7791289ec45a847c413edf686456']"

   strings:
      $hex_string = { a7cf3f5f7b8b81979a2fa0ed8a4f0d15129d5d50463632afec616b7791c0507e103a42e950a67bce4539bbd2f54b71a422791fd105fa56325ca301c23dbd5518 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
