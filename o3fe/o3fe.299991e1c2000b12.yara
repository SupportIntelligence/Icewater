
rule o3fe_299991e1c2000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3fe.299991e1c2000b12"
     cluster="o3fe.299991e1c2000b12"
     cluster_size="229"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="bitmin coinminer bitcoinminer"
     md5_hashes="['0000c2ad7facce74b89bf75d7e539f0b','03898f6535441db5dbe32fac4ba3ea48','1135efe8adbd779382645d192306cf27']"

   strings:
      $hex_string = { 00d6fa0e77cba3de89367dd36eb472a66ad7ae357c70cdaa17be03ab0b9a874e7314a9128f511d163d0d40533eb9e66d374a92e1ffb3a0c5f6313a59e0b5dd5b }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
