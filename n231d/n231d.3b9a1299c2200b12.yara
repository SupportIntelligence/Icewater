
rule n231d_3b9a1299c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231d.3b9a1299c2200b12"
     cluster="n231d.3b9a1299c2200b12"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos bankbot hqwar"
     md5_hashes="['d27e69b9f05e94c9aab2ec42332ab20f07bd61a6','6e3a8c2b47d2638c36741c4483823bc6898d568d','6cdd3a796fb29cc2fa9700efa7b5378c4267038e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231d.3b9a1299c2200b12"

   strings:
      $hex_string = { 33a8a7139af525e80c83d97592ae113f38cee4f3f9278d7ec37c0a66348b8985defcab32566aefe1c080dd21305f870f646ce218bed86dbbeb53d02f0ecdb471 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
