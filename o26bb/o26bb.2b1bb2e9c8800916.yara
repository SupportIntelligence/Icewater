
rule o26bb_2b1bb2e9c8800916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.2b1bb2e9c8800916"
     cluster="o26bb.2b1bb2e9c8800916"
     cluster_size="145"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious dangerousobject kryptik"
     md5_hashes="['ebee5af753a1c864136d4dc81e7d4ae8587c8d18','107f7b6ae51a10ea7da739e66586e62a3da02d92','a711979b4e1e56936dceaebecb60123b01d50f3d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.2b1bb2e9c8800916"

   strings:
      $hex_string = { cba98effbf9e8effad9291ffae9589ffb2a9a4feafb3b6f0898a8a9c504f4c130000000045b8466348d21eff409770f02214fcf32c27edff001cfdff2a30e260 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
