
rule o3e9_6114a48bc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.6114a48bc6220b12"
     cluster="o3e9.6114a48bc6220b12"
     cluster_size="658"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="lethic ayzg cryp"
     md5_hashes="['004ad7d499b2a77f44890e78007d89c5','01232c4cda964b2116a880d753f1864a','13db246e303263bc74536906f9efd274']"

   strings:
      $hex_string = { a0e146392a56830fe6cd564be0c79402751393e17373c79007314c6d5739fae1ab064d282b85ff8bf4014d537b6489073692b3b83199eefba51499daff5a1282 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
