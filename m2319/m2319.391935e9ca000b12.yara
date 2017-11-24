
rule m2319_391935e9ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.391935e9ca000b12"
     cluster="m2319.391935e9ca000b12"
     cluster_size="10"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="clicker faceliker script"
     md5_hashes="['01e2337958eb4bcb8ff052d86f37c823','2cb8da5e620c3a9a5cf2b865c2a84e76','f431bb766ce6cc99e755798702e976fa']"

   strings:
      $hex_string = { 38353231393930363139375c783236636f6c6f72735c78336443677430636d467563334268636d56756442494c64484a68626e4e7759584a6c626e516142794d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
