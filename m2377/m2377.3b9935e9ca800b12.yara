
rule m2377_3b9935e9ca800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.3b9935e9ca800b12"
     cluster="m2377.3b9935e9ca800b12"
     cluster_size="7"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="clicker faceliker script"
     md5_hashes="['23c961334b22f21f748377672d34aa7e','4697c83e8b000c912f2f9eced56c2b40','cb6b5df8ebaee54533217ccd68774a92']"

   strings:
      $hex_string = { 38353231393930363139375c783236636f6c6f72735c78336443677430636d467563334268636d56756442494c64484a68626e4e7759584a6c626e516142794d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
