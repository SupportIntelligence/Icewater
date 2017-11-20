
rule k3e9_2b14ad6994bb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2b14ad6994bb0b12"
     cluster="k3e9.2b14ad6994bb0b12"
     cluster_size="24"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy vbkrypt"
     md5_hashes="['0412fa422949d373c70869332d62e632','04ea5c16397a4682f6f9253e5a14ae35','b4cf0e0428815e7246f3c88e5d1792bb']"

   strings:
      $hex_string = { 1ec9cd8de4ce8864e786b32687b05203d9495a6eb846acd72a95729980bcbdeecbf06beff37d2683c366898402b54211a05107aa157aa534482d0e578ba2d4c2 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
