
rule m26bb_43b1c6d6b0994392
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.43b1c6d6b0994392"
     cluster="m26bb.43b1c6d6b0994392"
     cluster_size="83"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="gandcrab hpgandcrab malicious"
     md5_hashes="['66a5ff96d682700707652f24b535c158cf62e060','dde6ea0bbc79bd8a98c941eb3a9b5aa7ac80fcac','6ab7a37b6c20fc46485cdfae0c1c4998f6677c01']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.43b1c6d6b0994392"

   strings:
      $hex_string = { 0230c8d2f25ff386f5c0efed5e7b72e59253b5c65aa482fecc25e04bfb4c132a406e69e2e4011fd06c98387019acd5cb498522e18c242d7148561e8b069931ec }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
