
rule o26bb_289558f9c8800b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.289558f9c8800b16"
     cluster="o26bb.289558f9c8800b16"
     cluster_size="75"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik malicious dangerousobject"
     md5_hashes="['0ca58b433318092362e38f8223cf2e970f4b8ed8','610942ae5644f13af6c00b4b1cb7a2d6110e1518','4fc21b539f762600193a04ebd26b37b48f3187fc']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.289558f9c8800b16"

   strings:
      $hex_string = { cba98effbf9e8effad9291ffae9589ffb2a9a4feafb3b6f0898a8a9c504f4c130000000045b8466348d21eff409770f02214fcf32c27edff001cfdff2a30e260 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
