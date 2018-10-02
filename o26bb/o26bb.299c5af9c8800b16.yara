
rule o26bb_299c5af9c8800b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.299c5af9c8800b16"
     cluster="o26bb.299c5af9c8800b16"
     cluster_size="20"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik malicious dangerousobject"
     md5_hashes="['6cb271ff6fbab8fb364c874576b9bb0a8427b848','f4362a1e98431ab1d3d3facfedcc391f81171eab','62a12690263b12c1801bcb7c85d37b8c032f5c6f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.299c5af9c8800b16"

   strings:
      $hex_string = { cba98effbf9e8effad9291ffae9589ffb2a9a4feafb3b6f0898a8a9c504f4c130000000045b8466348d21eff409770f02214fcf32c27edff001cfdff2a30e260 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
