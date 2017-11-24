
rule k3e9_2b14ed6d969b0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2b14ed6d969b0b12"
     cluster="k3e9.2b14ed6d969b0b12"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba emotet vbkrypt"
     md5_hashes="['4697928ae402c98090dd2c430edf4ce4','8e3eff75faf2e867be7cc11a1b4567e1','bf2f787b0c8d551f0419334c64b55fbd']"

   strings:
      $hex_string = { 1eb0062c0153c004a8c21c27d930c7a9431f22c7b4547f4f2934c374fdbd24aa4dfa79a5eaef250a19c9c848a2331290a1d3a736776ebe355aafee8c3111ed58 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
