
rule n2319_2b993841c8000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.2b993841c8000912"
     cluster="n2319.2b993841c8000912"
     cluster_size="27"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="likejack faceliker script"
     md5_hashes="['2860ee709bda96bc71f22dec1a34e6dc49cc0a65','8c4de56c8c60d867cb417054cf8e47ebf2fb9533','9f26b0279a9db07be89501ea3dd16666573432d2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.2b993841c8000912"

   strings:
      $hex_string = { 6c3d662e737570706f72742e626f784d6f64656c3b76617220693d2f5e283f3a5c7b2e2a5c7d7c5c5b2e2a5c5d29242f2c6a3d2f285b612d7a5d29285b412d5a }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
