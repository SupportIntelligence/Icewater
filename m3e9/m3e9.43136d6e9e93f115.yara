
rule m3e9_43136d6e9e93f115
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.43136d6e9e93f115"
     cluster="m3e9.43136d6e9e93f115"
     cluster_size="229"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ibryte bundler installer"
     md5_hashes="['00d292bb1be5c89f207c792f842a6f6f','02a4c1d69935c61ed1afd8ace4d4749a','1f3a18122ff534ebdfee4ad518c3ce5c']"

   strings:
      $hex_string = { 5b5c5d5e5f6000004b4c4d15154e15154f505152535400003e3f40414243441545464748494a00003132333435363738393a3b3c3d00000025262728292a2b2c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
