
rule n3e9_19966849c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.19966849c0000b12"
     cluster="n3e9.19966849c0000b12"
     cluster_size="6"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod viking"
     md5_hashes="['0761e53013b21d709d934e36920ac062','14e940552174775f32c420839dfa72d0','87f18a9fae2e7dff33a80952467d4505']"

   strings:
      $hex_string = { 9c94812b5168cea348e798b9a789fddaff7a6ddfd9afd5ada88a7228557d646c3c8b5a66c7b21660d32ebd7e9f022362dd4e0107ac7b2ccd751dd22afc4c8384 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
