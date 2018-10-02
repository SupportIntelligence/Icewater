
rule o26bb_2c9458e9c8800b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.2c9458e9c8800b16"
     cluster="o26bb.2c9458e9c8800b16"
     cluster_size="234"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik malicious filerepmalware"
     md5_hashes="['c2371936f2ba91db5ee29986da1f69f8d9fbf488','5dc980a7318ec5f204f84c72162ea20cdce69688','e211c0399aa58a601c0db000863aa96cd02f74f0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.2c9458e9c8800b16"

   strings:
      $hex_string = { cba98effbf9e8effad9291ffae9589ffb2a9a4feafb3b6f0898a8a9c504f4c130000000045b8466348d21eff409770f02214fcf32c27edff001cfdff2a30e260 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
